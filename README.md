# v1-security-event-clustering

A security event clustering system with a Python FastAPI backend and a React-based frontend UI.

The repository includes:
- `backend/` — deep clustering, event parsing, threat analysis, and API endpoints.
- `frontend/` — UI components, charts, training controls, cluster visualization, and event upload.
- `docs/` — architecture, implementation notes, subsystem field reference, and testing guides.

## What this project does

The backend ingests raw security event logs, normalizes and vectorizes events, trains deep clustering models, and produces cluster analysis and security insights. The frontend provides an interface for uploading events, monitoring training progress, and exploring cluster results.

## Repository structure

- `backend/`
  - `main.py` — FastAPI service and API entrypoint
  - `event_parser.py` — raw event parsing and feature extraction
  - `deep_clustering.py` — DEC/IDEC/VaDE/contrastive/UFCM clustering models
  - `cluster_analyzer.py` — cluster threat scoring and analysis
  - `trainer.py` — training orchestration and model management
  - `security_insights.py` — insight generation and correlation analysis
  - `pyproject.toml` — backend Python package metadata
  - `requirements-linu.txt` / `requirements-win.txt` — install dependencies
- `frontend/`
  - `package.json` — build/dev scripts and dependencies
  - `webpack.config.cjs` — frontend bundling configuration
  - `src/` / `components/` — application UI and logic
- `docs/` — detailed design, architecture, testing, and subsystem documentation

## Prerequisites

### Backend
- Python 3.12+
- `pip` or another Python package manager
- Recommended: virtual environment

### Frontend
- Node.js 18+ / npm
- Optional: `yarn` or `pnpm`

## Backend setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-linu.txt
```

### Run backend locally

```bash
cd backend
uvicorn main:root_app --reload --host 0.0.0.0 --port 8000
```

The backend API is available at `http://localhost:8000/api`.

## Frontend setup

```bash
cd frontend
npm install
```

### Run frontend in development mode

```bash
cd frontend
npm run dev
```

### Build and serve production frontend

```bash
cd frontend
npm run build
npm start
```

The production build is served on `http://localhost:3001` by default.

## Usage

1. Start the backend (`uvicorn main:root_app --reload`).
2. Start the frontend (`npm run dev` or `npm start`).
3. Open the frontend in your browser and connect to the backend API.
4. Upload or submit raw security event logs.
5. Train models, inspect clusters, and review security insights.

## Key APIs

The backend exports the FastAPI app under `/api` and includes endpoints for:
- model training and job management
- prediction and cluster analysis
- security insights and event scoring
- batch event parsing and feature extraction

## Documentation

Read the `docs/` directory for detailed reference:
- `docs/backend.md` — backend architecture, workflow, and API overview
- `docs/ARCHITECTURE_DETAILS.md` — system design and data flow
- `docs/SUBSYSTEM_FIELDS.md` — supported security event fields and mappings
- `docs/QUICK_REFERENCE.md` — implementation checklist and troubleshooting
- `docs/TESTING_SUBSYSTEM_FIELDS.md` — test suites and validation guidance
- `docs/IMPLEMENTATION_SUMMARY.md` — code changes and integration notes

## Notes

- The backend is built with FastAPI and PyTorch.
- The frontend is a React application bundled with Webpack.
- The backend service is mounted at `root_app` and exposes routes prefixed by `/api`.
- The project includes both Windows and Linux dependency files under `backend/`.

## Contact

For development and debugging, start from `backend/main.py` and `backend/event_parser.py`, and refer to `docs/backend.md` for a full working model overview.
