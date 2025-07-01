# evtx-analyzer/app/main.py
import json
import xmltodict
import os
import shutil
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

# Create directories if they don't exist
UPLOAD_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)
JSONL_DIR.mkdir(exist_ok=True)

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
        print(f"Successfully parsed to {jsonl_output_path}")
    except Exception as e:
        print(f"Error parsing {evtx_path}: {e}")

def run_analysis(evtx_path: Path):
    """Runs Chainsaw, Hayabusa, and EVTX-to-JSONL parsing on a single file."""

    file_stem = evtx_path.stem  # e.g., "Security" from "Security.evtx"
    print(f"--- Starting analysis for {evtx_path.name} ---")

    # 1. Run Chainsaw
    chainsaw_output_file = RESULTS_DIR / f"{file_stem}_chainsaw_report.json"
    print(f"Running Chainsaw on {evtx_path.name}...")
    try:
        # Command: chainsaw hunt /path/to/file.evtx --json -o /path/to/output.json
        subprocess.run(
            ["chainsaw", "hunt", str(evtx_path), "--json", "-o", str(chainsaw_output_file)],
            check=True, capture_output=True, text=True
        )
        print(f"Chainsaw analysis complete. Report at: {chainsaw_output_file}")
    except subprocess.CalledProcessError as e:
        print(f"Chainsaw failed for {evtx_path.name}: {e.stderr}")
    except FileNotFoundError:
        print("Error: 'chainsaw' command not found. Is it in the system's PATH?")


    # 2. Run Hayabusa
    hayabusa_output_dir = RESULTS_DIR / f"{file_stem}_hayabusa_report"
    print(f"Running Hayabusa on {evtx_path.name}...")
    try:
        # Command: hayabusa -f /path/to/file.evtx -o /path/to/output_directory
        subprocess.run(
            ["hayabusa", "-f", str(evtx_path), "-o", str(hayabusa_output_dir)],
            check=True, capture_output=True, text=True
        )
        print(f"Hayabusa analysis complete. Report directory: {hayabusa_output_dir}")
    except subprocess.CalledProcessError as e:
        print(f"Hayabusa failed for {evtx_path.name}: {e.stderr}")
    except FileNotFoundError:
        print("Error: 'hayabusa' command not found. Is it in the system's PATH?")

    # 3. Parse EVTX to JSONL
    jsonl_output_file = JSONL_DIR / f"{file_stem}.jsonl"
    parse_evtx_to_jsonl(evtx_path, jsonl_output_file)

    print(f"--- Finished analysis for {evtx_path.name} ---")

# --- API Endpoints ---
@app.get("/", response_class=HTMLResponse)
async def get_upload_form(request: Request):
    """Serves the main upload page."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/evtx")
async def handle_file_upload(file: UploadFile = File(...)):
    """Handles file upload, extraction, and triggers analysis."""

    # Create a unique temporary directory for this upload session
    session_id = str(uuid.uuid4())
    session_dir:Path = UPLOAD_DIR / session_id
    session_dir.mkdir()

    upload_path = session_dir / file.filename

    try:
        # Save the uploaded file
        with upload_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Handle .zip archives
        if upload_path.suffix.lower() == ".zip":
            print(f"Extracting zip archive: {upload_path}")
            with zipfile.ZipFile(upload_path, 'r') as zip_ref:
                zip_ref.extractall(session_dir)
            upload_path.unlink() # Delete the zip file after extraction

        # Find all .evtx files in the session directory
        evtx_files = list(session_dir.glob('**/*.evtx'))
        if not evtx_files:
            # Handle case with no EVTX files (maybe bad zip or wrong file type)
            # For simplicity, we just redirect. A real app might show an error.
            print("No .evtx files found in the upload.")
        else:
            for evtx_file in evtx_files:
                run_analysis(evtx_file)

    finally:
        # Clean up the temporary upload session directory
        shutil.rmtree(session_dir)

    # Redirect user to the results page
    return RedirectResponse(url="/evtx-results", status_code=303)


@app.get("/evtx-results", response_class=HTMLResponse)
async def show_results(request: Request):
    """Scans the output directories and displays links to the results."""
    results_by_source = {}

    # Scan the results directory to find all generated reports
    all_files = list(RESULTS_DIR.rglob("*"))

    # Use the JSONL files as the source of truth for what was processed
    for jsonl_file in sorted(JSONL_DIR.glob("*.jsonl")):
        source_stem = jsonl_file.stem
        results_by_source[source_stem] = {
            "chainsaw": None,
            "hayabusa": None,
            "jsonl": str(jsonl_file) # Store the server path for display
        }

        # Find corresponding Chainsaw report
        chainsaw_report = RESULTS_DIR / f"{source_stem}_chainsaw_report.json"
        if chainsaw_report.exists():
            results_by_source[source_stem]["chainsaw"] = f"/static_results/{chainsaw_report.name}"

        # Find corresponding Hayabusa report (the main HTML file)
        hayabusa_dir = RESULTS_DIR / f"{source_stem}_hayabusa_report"
        if hayabusa_dir.is_dir():
            # Hayabusa reports can have different names, find the first .html
            try:
                html_report = next(hayabusa_dir.glob("*.html"))
                # The link needs to be relative to the static mount point
                relative_path = html_report.relative_to(RESULTS_DIR)
                results_by_source[source_stem]["hayabusa"] = f"/static_results/{relative_path}"
            except StopIteration:
                print(f"No HTML report found in {hayabusa_dir}")

    return templates.TemplateResponse("results.html", {
        "request": request,
        "results": results_by_source
    })