# evtx-analyzer/app/main.py
import json
import xmltodict
import os
import shutil
import logging
import subprocess
import uuid
import zipfile
from pathlib import Path

import Evtx.Evtx as evtx
from fastapi import FastAPI, File, UploadFile, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import asyncio
import queue
import threading

# --- Configuration ---
# Using pathlib for cleaner path management
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
RESULTS_DIR = BASE_DIR / "results"
JSONL_DIR = BASE_DIR / "jsonl_output"
LOG_DIR = Path("/logs") # Use absolute path for logs

# Create directories if they don't exist
UPLOAD_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)
# // JSONL_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

# --- Logging Configuration ---
# Create a queue for log messages to stream to clients
log_queue = queue.Queue()

class QueueHandler(logging.Handler):
    """Custom logging handler that puts log records into a queue for streaming."""
    def emit(self, record):
        log_entry = self.format(record)
        try:
            log_queue.put_nowait(log_entry)
        except queue.Full:
            pass  # Drop log if queue is full

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "app.log"),
        logging.StreamHandler(), # Also log to console
        QueueHandler() # Add our custom handler for streaming
    ]
)
logger = logging.getLogger(__name__)

# Create directories if they don't exist
# --- FastAPI App Initialization ---
app = FastAPI(title="EVTX Analysis Pipeline")

# Mount directories to serve static files (the reports)
app.mount("/static_results", StaticFiles(directory=RESULTS_DIR), name="static_results")

# Setup Jinja2 templates
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# --- Helper Functions ---
def parse_evtx_to_jsonl(evtx_path: Path, jsonl_output_path: Path):
    """Parses an EVTX file to a JSONL file, one JSON object per line."""
    print(f"Parsing {evtx_path} to {jsonl_output_path}...")
    logger.info(f"Parsing {evtx_path} to {jsonl_output_path}...")
    try:
        with jsonl_output_path.open("w") as f_out:
            with evtx.Evtx(str(evtx_path)) as log:
                for record in log.records():
                    # Convert the record to a dict for ease of parsing
                    data_dict = xmltodict.parse(record.xml())

                    # Initialize JSON object for this record
                    json_subline = {}

                    # Loop through each key,value pair of the System section of the evtx logs and extract the EventRecordID
                    for event_system_key, event_system_value in data_dict["Event"]["System"].items():
                        if event_system_key == "EventRecordID":
                            firstline = {event_system_key: event_system_value}
                            # Add information to the JSON object for this specific log
                            json_subline.update(firstline)  # add the event ID to JSON subline

                    # Loop through each key, value pair of the EventData section of the evtx logs
                    # Check if EventData exists first
                    if "EventData" not in data_dict["Event"]:
                        logger.warning(f"No EventData in record {json_subline.get('EventRecordID', 'unknown')}")
                        # Write the record even if it has no EventData, as it may still be useful
                        f_out.write(json.dumps(json_subline) + '\n')
                        continue

                    for event_data_key, event_data_value in data_dict["Event"]["EventData"].items():
                        for values in event_data_value:
                            # Initialize variables for each data pair
                            data_name = None
                            data_value = None

                            # Loop through each subvalue within the EventData section to extract necessary information
                            for event_data_subkey, event_data_subvalue in values.items():
                                if event_data_subkey == "@Name":
                                    data_name = event_data_subvalue
                                else:
                                    data_value = event_data_subvalue

                            # Add information to the JSON object for this specific log
                            if data_name is not None and data_value is not None:
                                json_subline.update({data_name: data_value})

                    # Write the JSON object as a single line to the JSONL file
                    f_out.write(json.dumps(json_subline) + '\n')
        logger.info(f"Successfully parsed to {jsonl_output_path}")
    except Exception as e:
        logger.error(f"Error parsing {evtx_path}: {e}")

def run_analysis(evtx_path: Path, ticket_number: str):
    """Runs Chainsaw, Hayabusa, and EVTX-to-JSONL parsing on a single file."""

    file_stem = evtx_path.stem  # e.g., "Security" from "Security.evtx"
    logger.info(f"--- Starting analysis for {evtx_path.name} (Ticket: {ticket_number}) ---")

    # 1. Run Chainsaw
    chainsaw_output_dir = RESULTS_DIR / ticket_number / file_stem
    chainsaw_output_dir.mkdir(parents=True, exist_ok=True)
    chainsaw_output_file = chainsaw_output_dir / f"{file_stem}_chainsaw_report.json"
    logger.info(f"Running Chainsaw on {evtx_path.name}...")
    try:
        # Command: chainsaw hunt /path/to/file.evtx --json -o /path/to/output.json
        subprocess.run(
            ["chainsaw", "hunt", str(evtx_path), "-s", "/sigma", "--mapping", "/chainsaw/mappings/sigma-event-logs-all.yml", "-r", "/chainsaw-rules", "--json", "-o", str(chainsaw_output_file)],
            check=True, capture_output=True, text=True
        )
        logger.info(f"Chainsaw analysis complete. Report at: {chainsaw_output_file}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Chainsaw failed for {evtx_path.name}: {e.stderr}")
    except FileNotFoundError:
        logger.error("Error: 'chainsaw' command not found. Is it in the system's PATH?")


    # 2. Run Hayabusa
    # Specify output path for the JSONL report
    hayabusa_jsonl_output = RESULTS_DIR / ticket_number / file_stem / f"{file_stem}_hayabusa_report.jsonl"
    # Specify output directory for the HTML report
    hayabusa_html_output_dir = RESULTS_DIR / ticket_number / file_stem
    hayabusa_html_output_dir.mkdir(parents=True, exist_ok=True) # Ensure directory exists
    hayabusa_html_output_file = hayabusa_html_output_dir / "index.html"

    logger.info(f"Running Hayabusa on {evtx_path.name}...")
    try:
        # Command: hayabusa json-timeline -f /path/to/file.evtx -L -o /path/to/output.jsonl -H /path/to/html_output_directory -w
        # -f specifies an evtx file as opposed to a directory (directory would be -d)
        # -L specifies JSONL output
        # -o tells it where to save the JSONL output
        # -H tells it where to save the HTML output
        # -w tells it to skip the CLI wizard so this stuff actually gets output and doesn't get hung up in the terminal
        result = subprocess.run(
            ["/opt/hayabusa/hayabusa", "json-timeline","-f", str(evtx_path), "-L", "-o", str(hayabusa_jsonl_output), "-H", str(hayabusa_html_output_file), "-w"],
            check=True, capture_output=True, text=True
        )
        # Log the subprocess output
        if result.stdout:
            logger.info(f"Hayabusa stdout: {result.stdout}")
        if result.stderr:
            logger.warning(f"Hayabusa stderr: {result.stderr}")

        logger.info(f"Hayabusa JSONL report at: {hayabusa_jsonl_output}")
        logger.info(f"Hayabusa HTML report directory: {hayabusa_html_output_dir}")

        # Check if the expected output files were actually created
        if not hayabusa_jsonl_output.exists():
            logger.error(f"Expected JSONL output file not created: {hayabusa_jsonl_output}")
        if not hayabusa_html_output_file.exists():
            logger.error(f"Expected HTML output file not created: {hayabusa_html_output_file}")

    except subprocess.CalledProcessError as e:
        logger.error(f"Hayabusa failed for {evtx_path.name}")
        logger.error(f"Return code: {e.returncode}")
        logger.error(f"Command: {e.cmd}")
        if e.stdout:
            logger.error(f"Stdout: {e.stdout}")
        if e.stderr:
            logger.error(f"Stderr: {e.stderr}")
    except FileNotFoundError:
        logger.error("Error: 'hayabusa' command not found. Is it in the system's PATH?")

    # 3. Parse EVTX to JSONL
    jsonl_output_file = RESULTS_DIR / ticket_number / file_stem / f"{file_stem}_dump.jsonl"
    parse_evtx_to_jsonl(evtx_path, jsonl_output_file)

    # 4. Copy all .json and .jsonl files to the JSONL directory
    # Convert .json files to .jsonl format for Splunk ingestion
    dest_dir = JSONL_DIR / ticket_number / file_stem
    dest_dir.mkdir(parents=True, exist_ok=True)

    src_dir = RESULTS_DIR / ticket_number / file_stem

    # Handle .json files - convert to JSONL format
    for src_file in src_dir.glob("*.json"):
        dest_file = dest_dir / f"{src_file.stem}.jsonl"
        try:
            with src_file.open('r', encoding='utf-8') as f:
                data = json.load(f)

            with dest_file.open('w', encoding='utf-8') as f:
                # If data is a list, write each item as a separate line
                if isinstance(data, list):
                    for item in data:
                        f.write(json.dumps(item) + '\n')
                # If data is a single object, write it as one line
                elif isinstance(data, dict):
                    f.write(json.dumps(data) + '\n')
                else:
                    # For other types, wrap in an object and write as one line
                    f.write(json.dumps({"data": data}) + '\n')

            logger.info(f"Converted JSON to JSONL: {src_file.name} -> {dest_file.name}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON file {src_file}: {e}")
            # Copy the file as-is if it can't be parsed
            shutil.copy2(src_file, dest_dir / src_file.name)
        except Exception as e:
            logger.error(f"Error converting {src_file} to JSONL: {e}")
            # Copy the file as-is if conversion fails
            shutil.copy2(src_file, dest_dir / src_file.name)

    # Handle .jsonl files - copy as-is
    for src_file in src_dir.glob("*.jsonl"):
        shutil.copy2(src_file, dest_dir / src_file.name)
        logger.info(f"Copied JSONL file: {src_file.name}")

    logger.info(f"--- Finished analysis for {evtx_path.name} (Ticket: {ticket_number}) ---")

# --- API Endpoints ---
@app.get("/", response_class=HTMLResponse)
async def get_upload_form(request: Request):
    """Serves the main upload page."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/logs/stream")
async def stream_logs():
    """Stream log messages in real-time using Server-Sent Events."""
    # Log that someone connected to the stream
    logger.info("Client connected to log stream")

    async def log_generator():
        # Send initial connection message
        yield f"data: Connected to log stream...\n\n"

        while True:
            try:
                # Try to get a log message from the queue (non-blocking)
                log_message = log_queue.get_nowait()
                yield f"data: {log_message}\n\n"
            except queue.Empty:
                # If no log message, send a heartbeat to keep connection alive
                yield f"data: \n\n"
                await asyncio.sleep(0.1)  # Wait 100ms before checking again

    return StreamingResponse(
        log_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Content-Type": "text/event-stream",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Cache-Control"
        }
    )

@app.post("/evtx")
async def handle_file_upload(file: UploadFile = File(...), ticket_number: str = Form(...)):
    """Handles file upload, extraction, and triggers analysis."""

    # Validate ticket number (basic validation)
    if not ticket_number or not ticket_number.strip():
        logger.error("Ticket number is required but was empty")
        return RedirectResponse(url="/?error=ticket_required", status_code=303)

    ticket_number = ticket_number.strip()
    logger.info(f"Processing upload for ticket: {ticket_number}")

    # Create a unique temporary directory for this upload session
    session_id = str(uuid.uuid4())
    session_dir:Path = UPLOAD_DIR / session_id
    session_dir.mkdir()

    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    upload_path = session_dir / file.filename

    try:
        # Save the uploaded file
        logger.info(f"Saving uploaded file: {file.filename}")
        with upload_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Handle .zip archives
        if upload_path.suffix.lower() == ".zip":
            logger.info(f"Extracting zip archive: {upload_path}")
            with zipfile.ZipFile(upload_path, 'r') as zip_ref:
                zip_ref.extractall(session_dir)
            upload_path.unlink() # Delete the zip file after extraction

        # Find all .evtx files in the session directory
        evtx_files = list(session_dir.glob('**/*.evtx'))
        if not evtx_files:
            # Handle case with no EVTX files (maybe bad zip or wrong file type)
            # For simplicity, we just redirect. A real app might show an error.
            logger.warning("No .evtx files found in the upload.")
        else:
            logger.info(f"Found {len(evtx_files)} EVTX file(s) to process")
            for evtx_file in evtx_files:
                run_analysis(evtx_file, ticket_number)

    finally:
        # Clean up the temporary upload session directory
        logger.info("Cleaning up temporary files")
        shutil.rmtree(session_dir)

    logger.info("Analysis complete - redirecting to results page")
    # Redirect user to the results page
    return RedirectResponse(url="/evtx-results", status_code=303)

@app.get("/evtx-results", response_class=HTMLResponse)
async def show_results(request: Request):
    results_by_ticket = {}

    # Now we have structure: RESULTS_DIR / {ticket_number} / {file_stem}
    for ticket_dir in sorted(RESULTS_DIR.iterdir()):
        if not ticket_dir.is_dir():
            continue

        ticket_number = ticket_dir.name
        results_by_ticket[ticket_number] = {}

        # Each ticket can have multiple file stems
        for source_dir in sorted(ticket_dir.iterdir()):
            if not source_dir.is_dir():
                continue

            stem = source_dir.name
            jsonl      = source_dir / f"{stem}_dump.jsonl"
            chainsaw   = source_dir / f"{stem}_chainsaw_report.json"
            hay_jsonl  = source_dir / f"{stem}_hayabusa_report.jsonl"
            html_index = source_dir / "index.html"

            results_by_ticket[ticket_number][stem] = {
                "jsonl":             f"/static_results/{ticket_number}/{stem}/{jsonl.name}"      if jsonl.exists()      else None,
                "chainsaw":          f"/static_results/{ticket_number}/{stem}/{chainsaw.name}"   if chainsaw.exists()   else None,
                "hayabusa_jsonl":    f"/static_results/{ticket_number}/{stem}/{hay_jsonl.name}"  if hay_jsonl.exists()  else None,
                "hayabusa_html":     f"/static_results/{ticket_number}/{stem}/{html_index.name}" if html_index.exists() else None,
            }

    return templates.TemplateResponse(
        "results.html",
        {"request": request, "results": results_by_ticket}
    )

@app.delete("/delete-results/{ticket_number}/{file_stem}")
async def delete_results(ticket_number: str, file_stem: str):
    """Deletes the results directory and all associated files for a specific file stem within a ticket."""

    try:
        # Construct the path to the results directory for this ticket and file stem
        results_dir_path = RESULTS_DIR / ticket_number / file_stem

        # Check if the directory exists
        if not results_dir_path.exists():
            logger.warning(f"Results directory not found: {results_dir_path}")
            raise HTTPException(status_code=404, detail=f"Results directory for '{file_stem}' in ticket '{ticket_number}' not found")

        if not results_dir_path.is_dir():
            logger.warning(f"Path exists but is not a directory: {results_dir_path}")
            raise HTTPException(status_code=400, detail=f"'{file_stem}' is not a valid results directory")

        # Delete the entire directory and its contents
        shutil.rmtree(results_dir_path)
        logger.info(f"Successfully deleted results directory: {results_dir_path}")

        # Also clean up the corresponding JSONL directory if it exists
        jsonl_dir_path = JSONL_DIR / ticket_number / file_stem
        if jsonl_dir_path.exists() and jsonl_dir_path.is_dir():
            shutil.rmtree(jsonl_dir_path)
            logger.info(f"Successfully deleted JSONL directory: {jsonl_dir_path}")

        # Check if the ticket directory is now empty and remove it if so
        ticket_results_dir = RESULTS_DIR / ticket_number
        if ticket_results_dir.exists() and ticket_results_dir.is_dir() and not any(ticket_results_dir.iterdir()):
            ticket_results_dir.rmdir()
            logger.info(f"Removed empty ticket directory: {ticket_results_dir}")

        ticket_jsonl_dir = JSONL_DIR / ticket_number
        if ticket_jsonl_dir.exists() and ticket_jsonl_dir.is_dir() and not any(ticket_jsonl_dir.iterdir()):
            ticket_jsonl_dir.rmdir()
            logger.info(f"Removed empty ticket JSONL directory: {ticket_jsonl_dir}")

        return JSONResponse(
            status_code=200,
            content={"message": f"Successfully deleted results for '{file_stem}' in ticket '{ticket_number}'"}
        )

    except PermissionError as e:
        logger.error(f"Permission denied when deleting {ticket_number}/{file_stem}: {e}")
        raise HTTPException(status_code=403, detail="Permission denied: Unable to delete results directory")

    except Exception as e:
        logger.error(f"Error deleting results for {ticket_number}/{file_stem}: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.delete("/delete-ticket/{ticket_number}")
async def delete_ticket(ticket_number: str):
    """Deletes all results for an entire ticket."""

    try:
        # Construct the path to the ticket directory
        ticket_results_dir = RESULTS_DIR / ticket_number
        ticket_jsonl_dir = JSONL_DIR / ticket_number

        deleted_something = False

        # Delete the results directory if it exists
        if ticket_results_dir.exists() and ticket_results_dir.is_dir():
            shutil.rmtree(ticket_results_dir)
            logger.info(f"Successfully deleted ticket results directory: {ticket_results_dir}")
            deleted_something = True

        # Delete the JSONL directory if it exists
        if ticket_jsonl_dir.exists() and ticket_jsonl_dir.is_dir():
            shutil.rmtree(ticket_jsonl_dir)
            logger.info(f"Successfully deleted ticket JSONL directory: {ticket_jsonl_dir}")
            deleted_something = True

        if not deleted_something:
            logger.warning(f"No directories found for ticket: {ticket_number}")
            raise HTTPException(status_code=404, detail=f"No results found for ticket '{ticket_number}'")

        return JSONResponse(
            status_code=200,
            content={"message": f"Successfully deleted all results for ticket '{ticket_number}'"}
        )

    except PermissionError as e:
        logger.error(f"Permission denied when deleting ticket {ticket_number}: {e}")
        raise HTTPException(status_code=403, detail="Permission denied: Unable to delete ticket directory")

    except Exception as e:
        logger.error(f"Error deleting ticket {ticket_number}: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")