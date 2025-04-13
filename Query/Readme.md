---
noteId: "45403780181d11f08f4e55be34bef22f"
tags: []

---

# Project SHADOW - Core Processing Layer

## Overview

The Core Processing Layer is the brain of Project SHADOW, responsible for analyzing agent queries, identifying relevant rules, enforcing security policies, and ensuring that agents only access information appropriate for their clearance level. This layer sits between the Authentication & Session Layer and the Response Generation Layer in the overall architecture.

## Components

The Core Processing Layer consists of four main components:

1. **Query Processing Service** - The central coordinator that manages the query processing pipeline
2. **NLP & Semantic Analysis Engine** - Analyzes and extracts meaning from raw agent queries
3. **Rules Matching Engine** - Identifies which rules match the agent's query
4. **Clearance Level Checker** - Enforces security policies based on agent clearance levels

## Architecture

![Core Processing Layer Architecture](core_processing_architecture.svg)

The components work together in the following flow:

1. An authenticated agent submits a query through the Secure Gateway Layer
2. The Query Processing Service receives the query and coordinates the analysis process
3. The NLP Engine analyzes the query to extract entities, intents, and other semantic information
4. The Rules Matcher identifies which of the 100 rules from the RAG CASE RESPONSE FRAMEWORK match the query
5. The Clearance Level Checker filters out rules that exceed the agent's clearance level
6. The Query Processing Service selects the best matching rule and forwards the result to the Response Generation Layer
7. Throughout this process, security checks are performed to detect anomalies or escalation attempts

## Component Details

### Query Processing Service (`query_processor.py`)

The Query Processing Service is the entry point for agent queries in the Core Processing Layer. It:

- Receives query requests from the Secure Gateway Layer
- Coordinates the analysis process across all components
- Detects security issues and reports them to the Security & Monitoring Layer
- Communicates with the Session Service to update session activity
- Forwards processed queries to the Response Generation Layer

### NLP & Semantic Analysis Engine (`nlp_engine.py`)

The NLP Engine extracts meaning from raw agent queries using natural language processing techniques. It:

- Normalizes and preprocesses the query text
- Extracts entities like operations, protocols, facilities, and code phrases
- Detects the agent's intent (e.g., extraction request, protocol inquiry)
- Identifies trigger phrases that match the framework rules
- Calculates query complexity to inform the response strategy
- Optionally uses an LLM for enhanced understanding (if available)

### Rules Matching Engine (`rules_matcher.py`)

The Rules Matcher identifies which of the 100 framework rules match the agent's query. It:

- Performs keyword matching to identify trigger phrases
- Uses vector similarity for semantic understanding (if embeddings available)
- Employs graph traversal to find related rules and concepts
- Combines multiple matching methods for optimal results
- Returns a ranked list of matching rules with confidence scores

### Clearance Level Checker (`level_checker.py`)

The Clearance Level Checker enforces security policies based on agent clearance levels. It:

- Verifies that agents have sufficient clearance for matched rules
- Handles special access policies (time-based, context-based)
- Filters out rules that exceed the agent's clearance level
- Detects escalation attempts when agents try to access restricted information
- Applies security policies to modify responses when necessary

## Integration with Other Layers

The Core Processing Layer integrates with other layers of the Project SHADOW architecture:

- **Authentication & Session Layer** - Receives agent information and session context
- **Security & Monitoring Layer** - Reports security events and anomalies
- **Response Generation Layer** - Forwards processed queries and selected rules
- **Data Persistence Layer** - Accesses the Rules Data Store and other databases

## Security Features

The Core Processing Layer implements several security features to protect classified information:

- **Clearance Level Enforcement** - Ensures agents can only access information at their clearance level
- **Escalation Attempt Detection** - Identifies when agents try to access restricted information
- **Special Access Policies** - Enforces time-based and context-based restrictions
- **Cryptic Response Generation** - Provides obscured information for certain queries
- **Comprehensive Logging** - Tracks all query processing for audit purposes

## Implementation Details

### Query Processing Flow

1. **Receive Query Request**
   - Validate request parameters
   - Extract agent information

2. **NLP Analysis**
   - Normalize and preprocess the query
   - Extract entities and intents
   - Identify trigger phrases

3. **Rule Matching**
   - Find matching rules using hybrid approach
   - Rank rules by relevance

4. **Clearance Checking**
   - Filter rules based on agent clearance
   - Check for escalation attempts
   - Apply special access policies

5. **Generate Result**
   - Select the best matching rule
   - Apply security policies
   - Forward to Response Generation Layer

### Response Types

Based on the query analysis and security checks, the system can generate different types of responses:

1. **Direct Response** - Provides the information requested (when clearance is sufficient)
2. **Cryptic Response** - Returns a vague or indirect answer (for sensitive information)
3. **Denial Response** - Refuses to provide information (when clearance is insufficient)
4. **Directive Response** - Returns a specific predetermined message (for special trigger phrases)
5. **Fallback Response** - Used when no matching rule is found

## Setting Up and Running

### Prerequisites

- Python 3.8+
- Required packages: FastAPI, Uvicorn, httpx, spaCy, and optional packages for advanced features

### Installation

1. Install required packages:
   ```
   pip install fastapi uvicorn httpx spacy
   ```

2. Download SpaCy model:
   ```
   python -m spacy download en_core_web_md
   ```

3. Optional: Install additional packages for advanced features:
   ```
   pip install sentence-transformers langchain
   ```

### Configuration

Configure the Core Processing Layer using environment variables:

- `RULES_FILE_PATH` - Path to the rules JSON file (default: `data.json`)
- `INTERNAL_API_KEY` - API key for internal service communication
- `SECURITY_SERVICE_URL` - URL for the Security Service
- `RESPONSE_GEN_URL` - URL for the Response Generation Service
- `SESSION_SERVICE_URL` - URL for the Session Service

### Running the Services

Start each component separately:

```
# Start the Query Processing Service
uvicorn query_processor:app --host 0.0.0.0 --port 8003

# Run tests
python test_core_processing.py
```

## Extending the System

### Adding New Rules

To add new rules to the system:

1. Update the `data.json` file with new rule definitions
2. Restart the services to reload the rules

### Implementing Advanced Features

The Core Processing Layer supports several advanced features that can be enabled:

- **Vector Embeddings** - Enable by setting `use_embeddings=True` in the RulesMatcher constructor
- **LLM Integration** - Enable by setting `use_llm=True` in the NLPEngine constructor
- **Custom Entity Recognition** - Add domain-specific entities to the NLP Engine

## Security Considerations

The Core Processing Layer implements several security measures:

- **Zero-Trust Model** - Validates every query against clearance levels
- **Defense in Depth** - Multiple layers of security checks
- **Principle of Least Privilege** - Agents only see information at their clearance level
- **Audit Logging** - Comprehensive logging for security analysis

## Troubleshooting

Common issues and solutions:

- **Slow Query Processing** - Check for LLM or embedding computation overhead
- **Missing Rule Matches** - Verify the rules file and trigger phrases
- **Clearance Check Failures** - Confirm agent levels and rule requirements

## Conclusion

The Core Processing Layer is the central intelligence hub of Project SHADOW, ensuring that agent queries are properly analyzed, matched with relevant rules, and subjected to appropriate security checks. By coordinating the NLP Engine, Rules Matcher, and Clearance Level Checker, it maintains the delicate balance between information access and security required for a classified intelligence system.