# Installation and Setup Guide

## Project SHADOW Advanced RAG System

**Security Classification: Level 7**  
**Last Updated: April 2025**  
**Document Version: 3.7.2**  
**Directorate of Covert Operations**

## Prerequisites

- Python 3.10+
- Docker and Docker Compose (for containerized deployment)
- 8GB+ RAM (16GB+ recommended for production)
- 2+ CPU cores (4+ recommended for production)
- 20GB+ disk space

## Local Installation

### 1. Clone the Repository

```bash
git clone [REPOSITORY_URL] project-shadow
cd project-shadow
```

### 2. Set Up Environment

Create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Configure Environment Variables

```bash
cp .env.example .env
```

Edit the `.env` file and set your configuration:

- Generate a secure `API_KEY` and `INTERNAL_API_KEY`
- Set `ANTHROPIC_API_KEY` if using Anthropic for response generation
- Adjust paths and other settings as needed

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Initialize Data Directory

```bash
mkdir -p data/vector_store data/graph_store
cp path/to/data.json data/
```

### 6. Start the Services

For development:

```bash
python -m uvicorn main:app --reload
```

For production:

```bash
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

## Docker Deployment

### 1. Build and Start Containers

```bash
cp .env.example .env
# Edit .env file with your configuration
docker-compose build
docker-compose up -d
```

### 2. Check Service Status

```bash
docker-compose ps
```

### 3. View Logs

```bash
docker-compose logs -f
```

## Component Initialization

When first started, the system will:

1. Initialize the Vector Store with embeddings for all rules
2. Build the Knowledge Graph with rule relationships
3. Prepare the Hybrid Retrieval Engine
4. Set up the Mosaic Anomaly Detection system

This initialization may take a few minutes depending on the hardware.

## Verifying Installation

### 1. Check API Health

```bash
curl http://localhost:8000/health
```

Expected response:

```json
{"status":"ok","timestamp":"2025-04-15T10:30:45.123456"}
```

### 2. Check System Status

```bash
curl -H "X-API-Key: your-api-key-here" http://localhost:8000/system/status
```

You should see detailed status information for all components.

## Authentication and First Query

### 1. Authenticate Agent

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "X-API-Key: your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "agent001", "clearance_level": 1, "credentials": {"username": "test_agent", "password": "test_password"}}'
```

Save the `session_id` and `token` from the response.

### 2. Submit a Query

```bash
curl -X POST http://localhost:8000/agent/query \
  -H "X-API-Key: your-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"query_text": "omega echo", "agent_id": "agent001", "agent_level": 1, "session_id": "SESSION_ID_FROM_PREVIOUS_STEP"}'
```

## Security Recommendations

1. Always use HTTPS in production
2. Rotate API keys regularly
3. Set up proper firewall rules
4. Enable audit logging
5. Monitor system regularly for anomalies

## Troubleshooting

### API Not Starting

- Check if ports are already in use
- Verify environment variables are set correctly
- Check logs for error messages

### Vector Store Initialization Failing

- Ensure enough disk space and memory
- Check if embedding model is accessible
- Verify rules data file is correctly formatted

### Authentication Issues

- Check API key configuration
- Verify authentication service is running
- Check network connectivity between services

For further assistance, contact the Project SHADOW support team. 
noteId: "0c34d72017be11f08f4e55be34bef22f"
tags: []

---

 