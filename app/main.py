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
from fastapi import FastAPI, File, UploadFile, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

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
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "app.log"),
        logging.StreamHandler() # Also log to console
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
                final_json = []
                for record in log.records():
                    # // f_out.write(record['data'] + '\n')
                    #. Convert the record to a dict for ease of parsing
                    data_dict = xmltodict.parse(record.xml())

                    # Loop through each key,value pair of the System section of the evtx logs and extract the EventRecordID
                    for event_system_key, event_system_value in data_dict["Event"]["System"].items():
                        if event_system_key == "EventRecordID":
                            json_subline = {}
                            firstline = {event_system_key: event_system_value}

                            # Add information to the JSON object for this specific log
                            json_subline.update(firstline)  # add the event ID to JSON subline

                    # Loop through each key, value pair of the EventData section of the evtx logs
                    # Check if EventData exists first
                    if "EventData" not in data_dict["Event"]:
                        logger.warning(f"No EventData in record {json_subline.get('EventRecordID', 'unknown')}")
                        continue

                    for event_data_key, event_data_value in data_dict["Event"]["EventData"].items():
                        for values in event_data_value:

                            # Loop through each subvalue within the EvenData section to extract necessary information
                            for event_data_subkey, event_data_subvalue in values.items():
                                if event_data_subkey == "@Name":
                                    data_name = event_data_subvalue
                                else:
                                    data_value = event_data_subvalue

                                    # Add information to the JSON object for this specific log
                                    json_subline.update({data_name: data_value})

                    # Add specific log JSON object to the final JSON object
                    if not final_json:
                        final_json = [json_subline]
                    else:
                        final_json.append(json_subline)
                    json.dump(final_json, f_out)
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
    dest_dir = JSONL_DIR / ticket_number / file_stem
    dest_dir.mkdir(parents=True, exist_ok=True)
    
    src_dir = RESULTS_DIR / ticket_number / file_stem
    for pattern in ("*.json", "*.jsonl"):
        for src_file in src_dir.glob(pattern):
            shutil.copy2(src_file, dest_dir / src_file.name)

    logger.info(f"--- Finished analysis for {evtx_path.name} (Ticket: {ticket_number}) ---")

# --- API Endpoints ---
@app.get("/", response_class=HTMLResponse)
async def get_upload_form(request: Request):
    """Serves the main upload page."""
    return templates.TemplateResponse("index.html", {"request": request})

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

    upload_path = session_dir / (file.filename or "uploaded_file")

    try:
        # Save the uploaded file
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
            for evtx_file in evtx_files:
                run_analysis(evtx_file, ticket_number)

    finally:
        # Clean up the temporary upload session directory
        shutil.rmtree(session_dir)

    # Redirect user to the results page
    return RedirectResponse(url="/evtx-results", status_code=303)

'''
@app.get("/evtx-results", response_class=HTMLResponse)
async def show_results(request: Request):
    """Scans the output directories and displays links to the results."""
    results_by_source = {}

    # Scan the results directory to find all generated reports
    all_files = list(RESULTS_DIR.rglob("*"))

    # Use the JSONL files as the source of truth for what was processed
    # // for jsonl_file in sorted(RESULTS_DIR.glob("*.jsonl")):
    for jsonl_file in sorted(JSONL_DIR.glob("*.jsonl")):
        source_stem = jsonl_file.stem

        results_by_source[source_stem] = {
            "chainsaw": None,
            "hayabusa_html": None, # Explicitly for HTML report
            "hayabusa_jsonl": None, # Explicitly for JSONL report
            "jsonl": str(jsonl_file) # Store the server path for display
        }

        # Find corresponding Chainsaw report
        chainsaw_report = RESULTS_DIR / f"{source_stem}_chainsaw_report.json"
        if chainsaw_report.exists():
            results_by_source[source_stem]["chainsaw"] = f"/static_results/{chainsaw_report.name}"

        # Find corresponding Hayabusa report (the main HTML file)
        # Now explicitly store HTML and JSONL separately
        hayabusa_dir = RESULTS_DIR / f"{source_stem}_hayabusa_report" # This is the HTML output directory

        if hayabusa_dir.is_dir():
            # Hayabusa reports can have different names, find the first .html
            try:
                html_report = next(hayabusa_dir.glob("*.html"))
                # The link needs to be relative to the static mount point
                results_by_source[source_stem]["hayabusa_html"] = f"/static_results/{html_report.relative_to(RESULTS_DIR)}"
            except StopIteration:
                logger.error(f"No HTML report found in {hayabusa_dir}")

        # Find corresponding Hayabusa JSONL report
        hayabusa_jsonl = RESULTS_DIR / f"{source_stem}_hayabusa_report.jsonl"
        if hayabusa_jsonl.exists():
            results_by_source[source_stem]["hayabusa_jsonl"] = f"/static_results/{hayabusa_jsonl.name}"
    return templates.TemplateResponse("results.html", {
        "request": request,
        "results": results_by_source
    })
'''

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