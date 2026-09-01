# Nexus One

AI-powered Security Operations Center (SOC) platform built with FastAPI.

## Features (Planned)

- Security event ingestion and normalization
- Rule-based detection engine
- ML-based anomaly detection
- Event correlation and incident creation
- Risk scoring and attack timeline reconstruction
- AI-assisted incident investigation
- Response recommendations
- SOC dashboard

## Current Status

Detection (rule + ML), event correlation, risk scoring, attack timeline reconstruction, the AI-powered incident investigation layer, response recommendations, and incident reporting are implemented. Remaining stubs: authentication, SOC dashboard frontend, and real-time ingestion pipelines.

## Architecture

```
nexus-one/
├── app/
│   ├── api/              # FastAPI routers
│   │   ├── v1/          # Versioned API endpoints
│   │   └── health.py    # Health check endpoints
│   ├── models/          # SQLAlchemy ORM models
│   ├── schemas/         # Pydantic request/response schemas
│   ├── services/        # Business logic layer
│   ├── detection/       # Rule-based detection engine
│   ├── correlation/     # Event correlation engine
│   ├── ml/              # ML anomaly detection
│   ├── risk/            # Deterministic risk scoring
│   ├── timeline/        # Attack timeline reconstruction
│   ├── ai/              # AI investigation (provider, prompts, validation)
│   ├── response/        # Deterministic response recommendation engine
│   └── reports/         # Incident report generation (JSON + HTML)
├── tests/               # Test suite
├── main.py              # Application entry point
└── requirements.txt     # Python dependencies
```

## Setup

### Prerequisites

- Python 3.9+
- pip

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd nexus-one
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Copy environment configuration:
```bash
cp .env.example .env
```

5. (Optional) Edit `.env` to customize settings.

### Running the Application

Start the development server:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at:
- **API**: http://localhost:8000
- **Interactive docs**: http://localhost:8000/docs
- **Alternative docs**: http://localhost:8000/redoc

### Testing

Run the test suite:
```bash
pytest
```

Run with coverage:
```bash
pytest --cov=app --cov-report=html
```

## API Endpoints

### Health & Status
- `GET /` — Root endpoint with app info
- `GET /health` — Health check

### Events (v1)
- `POST /api/v1/events/` — Create a security event
- `GET /api/v1/events/` — List events

### Incidents (v1)
- `POST /api/v1/incidents/correlate` — Run event correlation
- `GET /api/v1/incidents/` — List incidents
- `GET /api/v1/incidents/{id}` — Incident detail
- `GET /api/v1/incidents/{id}/risk` — Deterministic risk score
- `GET /api/v1/incidents/{id}/timeline` — Attack timeline
- `GET /api/v1/incidents/{id}/summary` — Incident + risk + timeline bundle
- `POST /api/v1/incidents/{id}/investigate` — Run an AI investigation
- `GET /api/v1/incidents/{id}/investigation` — Latest persisted AI investigation
- `GET /api/v1/incidents/{id}/recommendations` — Prioritized advisory response recommendations
- `POST /api/v1/incidents/{id}/report` — Generate (and persist) an incident report (`?format=json|html`)
- `GET /api/v1/incidents/{id}/report` — Latest persisted incident report (`?format=json|html`)

## AI Investigation Layer

The AI layer produces a structured investigation report for a correlated
incident: summary, threat assessment, attack narrative, findings with
evidence citations, uncertainties, and recommended next steps for analysts.

Design principles:

- **Evidence-first**: the LLM only ever receives a structured
  "observed evidence" payload built from the incident, its alerts, the
  deterministic risk assessment, and the attack timeline — no database or
  application internals.
- **No fabrication**: the system prompt forbids inventing events, IPs, users,
  hosts, or timestamps, and requires explicit uncertainties when evidence is
  insufficient.
- **Validated citations**: every finding must cite evidence IDs
  (`alert-<id>` / `event-<id>`) that were actually supplied; unsupported
  citations are rejected (HTTP 502).
- **Deterministic severity**: the numerical risk score always comes from the
  deterministic risk engine — the LLM narrates but never scores.
- **Analysis only**: the AI never executes commands or performs response
  actions; recommendations are for a human analyst.

### Configuration

The provider is environment-configured and replaceable (see `.env.example`):

| Variable | Default | Purpose |
| --- | --- | --- |
| `LLM_PROVIDER` | auto | `openai`, `demo`, or unset (auto: `openai` when a key exists, else unconfigured) |
| `LLM_API_KEY` | — | API key for the OpenAI-compatible provider |
| `LLM_MODEL` | `gpt-4o-mini` | Model name |
| `LLM_BASE_URL` | `https://api.openai.com/v1` | Any OpenAI-compatible chat-completions endpoint |
| `LLM_TIMEOUT_SECONDS` | `60` | Provider timeout |
| `LLM_MAX_CONTEXT_CHARS` | `100000` | Evidence context size cap (HTTP 413 beyond) |
| `LLM_MAX_ALERTS_IN_CONTEXT` | `50` | Chronological alert cap in evidence |

Without an API key the app starts normally and all non-AI features work;
the investigation endpoints return a clear configuration error (HTTP 400).

### Demo mode

`LLM_PROVIDER=demo` selects a deterministic offline DEMO/MOCK provider that
generates a realistic structured investigation purely from the supplied
evidence (never inventing entities and citing only supplied IDs). Responses
are labelled `DEMO (deterministic mock provider - not a live LLM)`. This is
the mode used in local development and CI; no paid LLM calls are made.

## Response Recommendations & Incident Reports

The response layer generates prioritized, evidence-based recommendations
from incident evidence plus the AI investigation. The report layer assembles
everything into a structured incident report (machine-readable JSON first,
HTML rendering via `?format=html`).

Design principles:

- **Deterministic prioritization**: priority scores come from a transparent,
  configurable rule engine (base score per recommendation type + boosts for
  risk level, severity, evidence count, multi-stage activity, and
  investigation availability) — never from an LLM.
- **Advisory only**: every recommendation carries
  `requires_analyst_approval: true`; Nexus One never executes response
  actions (no blocking, disabling, isolating, or deleting).
- **Validated evidence citations**: recommendations cite only real
  `alert-<id>` / `event-<id>` identifiers from the incident.
- **Evidence vs analysis separation**: reports clearly separate observed
  evidence (Section 1) from analysis and inference (Section 2, including AI
  narrative labelled as such) and recommended actions (Section 3).
- **Graceful degradation**: reports and recommendations work with or without
  an AI investigation; when absent, the report says so and lists it as an
  uncertainty.

## Database

SQLite is used for local development. The schema is automatically created on first run.

`Base.metadata.create_all()` creates missing tables only; it does not add or alter columns in an existing database. Until a migration tool is intentionally introduced, recreate local SQLite databases after incompatible development schema changes.

To switch to PostgreSQL for production, update `DATABASE_URL` in `.env`:
```
DATABASE_URL=postgresql://user:password@localhost:5432/nexus_one
```

## Configuration

All configuration is managed via environment variables in `.env`. See `.env.example` for available options:

- `APP_NAME` — Application name
- `APP_ENV` — Environment (development/production)
- `DEBUG` — Enable debug mode
- `DATABASE_URL` — Database connection string
- `SECRET_KEY` — Security key (change in production)
- `API_V1_PREFIX` — API version prefix

## Next Steps

- Create SOC dashboard frontend
- Add authentication and authorization
- Implement event ingestion pipelines
- Add WebSocket support for real-time updates

## License

MIT
