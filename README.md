# chayabusaw
Simple interface for analyzing EVTX logs with Chainsaw and Hayabusa

This project provides a containerized web application to automate the analysis of Windows Event Log (.evtx) files. Users can upload `.evtx` files or `.zip` archives containing them. The backend processes each file with **Chainsaw** and **Hayabusa**, parses the raw logs into JSONL format, and presents the analysis reports on a clean web interface.

The entire application is deployed using a single `docker-compose.yaml` file, designed to be launched with **Podman**.

## Prerequisites

- **Podman**: [Installation Guide](https://podman.io/getting-started/installation)
- **podman-compose**: You can typically install this via `pip install podman-compose`.

## Setup and Deployment

1.  **Clone the Repository**

    ```sh
    git clone <your-repository-url>
    cd chayabusaw
    ```

2.  **Create Host Directories for Persistent Storage**

    The application uses host-mounted volumes to store analysis results and parsed logs persistently. You must create these directories on your host machine before starting the application.

    ```sh
    mkdir analysis_results
    mkdir evtx_jsonl_output
    ```

3.  **Build the Container Image**

    Use `podman-compose` to build the image defined in the `Dockerfile`. This will download the base image, install dependencies, and set up the analysis tools (Chainsaw and Hayabusa).

    ```sh
    podman-compose build
    ```

4.  **Launch the Application**

    Run the application in detached mode (`-d`).

    ```sh
    podman-compose up -d
    ```

    You can check the container status with `podman ps` and view logs with `podman logs chayabusaw-app`.

## How to Use

1.  **Access the Web UI**
    Open your web browser and navigate to `http://localhost:8000`.

2.  **Upload Files**
    Use the web form to select a single `.evtx` file or a `.zip` archive containing multiple `.evtx` files.

3.  **Analyze**
    Click the "Analyze File(s)" button. A processing message will appear. The analysis time depends on the size and number of the log files.

4.  **View Results**
    Once processing is complete, you will be redirected to the results page. This page will display links to the generated reports from Chainsaw and Hayabusa, grouped by the original EVTX filename.

5.  **Access Persistent Data**
    - The analysis reports (JSON from Chainsaw, HTML from Hayabusa) will be available in the `analysis_results/` directory on your host machine.
    - The raw event logs parsed into JSONL format will be stored in the `evtx_jsonl_output/` directory on your host machine. These are not directly downloadable from the UI but are persistently stored for further offline analysis.
    - Custom rules can be loaded into the container by mounting a volume at `/custom-sigma-rules` and `/custom-chainsaw-rules`. These will be merged into the default rules in the container.
    **NOTE** At the moment custom rules only work on Chainsaw. TODO: figure out how to use the same custom sigma rules in Hayabusa.

## Project Structure

```txt
evtx-analyzer/
├── app/
│   ├── main.py             # FastAPI application logic
│   ├── templates/
│   │   ├── index.html      # Upload form template
│   │   └── results.html    # Results display template
├── chainsaw                # Contains chainsaw binary and rules
├── Dockerfile              # Defines the application container image
├── docker-compose.yaml     # Orchestrates the service deployment
├── README.md               # This file
└── requirements.txt        # Python dependencies
```
