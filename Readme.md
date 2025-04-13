---
noteId: "24e2172017bd11f08f4e55be34bef22f"
tags: []

---

# PROJECT SHADOW - Advanced RAG System

## Classified Intelligence Retrieval System

**Security Classification: Level 7**  
**Last Updated: April 2025**  
**Document Version: 3.7.2**  
**Directorate of Covert Operations**

---

## Table of Contents

1. [Executive Overview](#executive-overview)
2. [System Architecture](#system-architecture)
   - [Architectural Layers](#architectural-layers)
   - [Component Interaction](#component-interaction)
   - [Data Flow](#data-flow)
3. [Advanced RAG Layer](#advanced-rag-layer)
   - [Core Components](#core-components)
   - [Retrieval Methodologies](#retrieval-methodologies)
   - [Security Integration](#security-integration)
4. [Vector Store Implementation](#vector-store-implementation)
   - [Embedding Generation](#embedding-generation)
   - [Indexing Strategies](#indexing-strategies)
   - [Search Optimization](#search-optimization)
5. [Knowledge Graph System](#knowledge-graph-system)
   - [Graph Structure](#graph-structure)
   - [Relationship Types](#relationship-types)
   - [Traversal Algorithms](#traversal-algorithms)
6. [Hybrid Retrieval Engine](#hybrid-retrieval-engine)
   - [Retrieval Modes](#retrieval-modes)
   - [Scoring Mechanisms](#scoring-mechanisms)
   - [Context Adaptation](#context-adaptation)
7. [Security Framework](#security-framework)
   - [Clearance Level Management](#clearance-level-management)
   - [Mosaic Anomaly Detection](#mosaic-anomaly-detection)
   - [Neural Signature Verification](#neural-signature-verification)
8. [Response Generation](#response-generation)
   - [Agent-Level Greetings](#agent-level-greetings)
   - [Rule-Based Formatting](#rule-based-formatting)
   - [Information Scrambling](#information-scrambling)
9. [Encryption Layer](#encryption-layer)
   - [Layered Cipher Code (LCC)](#layered-cipher-code-lcc)
   - [Ghost-Step Algorithm](#ghost-step-algorithm)
   - [Quantum Hashing](#quantum-hashing)
10. [Authentication & Session Management](#authentication--session-management)
    - [Handshake Protocol](#handshake-protocol)
    - [Session Integrity Protection](#session-integrity-protection)
    - [Token Management](#token-management)
11. [Deployment Guide](#deployment-guide)
    - [System Requirements](#system-requirements)
    - [Installation Procedure](#installation-procedure)
    - [Configuration Options](#configuration-options)
12. [Operation Procedures](#operation-procedures)
    - [Startup Sequence](#startup-sequence)
    - [Maintenance Tasks](#maintenance-tasks)
    - [Emergency Protocols](#emergency-protocols)
13. [Development Guide](#development-guide)
    - [Codebase Structure](#codebase-structure)
    - [Extension Points](#extension-points)
    - [Testing Framework](#testing-framework)
14. [Security Considerations](#security-considerations)
    - [Threat Modeling](#threat-modeling)
    - [Vulnerability Management](#vulnerability-management)
    - [Intrusion Detection](#intrusion-detection)
15. [Performance Optimization](#performance-optimization)
    - [Benchmarks](#benchmarks)
    - [Scaling Strategies](#scaling-strategies)
    - [Resource Management](#resource-management)
16. [Appendix](#appendix)
    - [API Reference](#api-reference)
    - [Rule Framework Schema](#rule-framework-schema)
    - [Glossary](#glossary)

---

## Executive Overview

Project SHADOW is an advanced intelligence retrieval system designed for RAW (Research and Analysis Wing) agents with varying clearance levels. It implements a sophisticated Retrieval-Augmented Generation (RAG) architecture that securely delivers information based on agent authorization, query context, and operational security requirements.

The system is built to handle sensitive intelligence information while strictly enforcing the RAG CASE RESPONSE FRAMEWORK, ensuring that agents only receive information appropriate to their clearance level and operational need-to-know. It combines vector-based similarity search, knowledge graph traversal, and rule-based response generation to deliver accurate intelligence while preserving security boundaries.

Key capabilities include:

- **Advanced hybrid retrieval system** combining vector search, graph traversal, and rule-based matching
- **Multi-level clearance enforcement** with granular access control and response formatting
- **Mosaic Anomaly Detection** to identify suspicious query patterns or security breaches
- **Neural signature verification** for high-security operations requiring biometric confirmation
- **Secure encrypted communication** using the Layered Cipher Code system with quantum resistance
- **Real-time security monitoring** with the ability to isolate or terminate compromised sessions
- **Agent-specific response formatting** based on clearance level, operational context, and security protocols

Project SHADOW operates on a zero-trust security model where every transaction is verified, monitored, and logged for audit purposes. The system's modular architecture allows for continuous improvement and adaptation to evolving intelligence needs and security threats.

---

## System Architecture

### Architectural Layers

Project SHADOW follows a layered architecture designed for security, scalability, and modularity. Each layer has specific responsibilities and security boundaries to ensure compartmentalization of sensitive operations.

1. **Client Layer**
   - Agent Terminal (Level 1-5 Operative)
   - Secure Agent Interface (UI/CLI)

2. **Secure Gateway Layer**
   - Secure API Gateway (TLS + Custom Encryption)
   - Handshake Protocol Verifier

3. **Authentication & Session Layer**
   - Authentication Service
   - Agent Session Manager
   - Neural Signature Verification

4. **Core Processing Layer**
   - Query Processing Service
   - NLP & Semantic Analysis Engine
   - Rules Matching Engine
   - Clearance Level Checker

5. **Advanced RAG Layer**
   - Vector Store (FAISS)
   - Knowledge Graph Database
   - Hybrid Retrieval Engine

6. **Response Generation Layer**
   - Response Generation Service
   - Agent-Level Greeting Formatter
   - Response Content Formatter
   - Information Scrambler (when required)

7. **Security & Monitoring Layer**
   - Security & Anomaly Detection Service
   - Mosaic Anomaly Detection
   - Query Pattern Analyzer
   - Threat Assessment Engine
   - Protocol Zeta-5 (Kill-Switch)

8. **Encryption Layer**
   - Layered Cipher Code (LCC) System
   - Quantum Hashing Module
   - One-Time Pad Generator & Manager
   - Ghost-Step Algorithm

9. **Data Persistence Layer**
   - Agent Profile & Clearance Database
   - Rules Data Store (JSON)
   - Encrypted Audit Trail Database
   - Neural Signatures Database

10. **Logging & Audit Layer**
    - Audit & Logging Service
    - Forensic Analysis Tools
    - Tamper-Proof Logging

### Component Interaction

The components interact through secure, authenticated channels with strict access controls and encrypted communications. The diagram below illustrates the primary interaction paths:

```
Agent → Secure UI → API Gateway → Auth Service → Session Manager
                                     ↓
Query Processing → NLP Engine → Rules Matcher → Level Checker → Vector Store
                                                             → Knowledge Graph
                                                             → Hybrid Retrieval
                                     ↓
Response Generation → Greeting Formatter → Response Formatter → Scrambler
                                                                  ↓
LCC Encryption → Quantum Hashing → OTP → Ghost-Step → API Gateway → Agent

[Security Monitor continuously observes all interactions]
```

All communications between components are encrypted and authenticated, with session tokens and access controls validated at each step. The Security Monitor observes all interactions in real-time to detect anomalous patterns or potential security breaches.

### Data Flow

1. **Authentication Flow**
   - Agent provides credentials through secure interface
   - API Gateway forwards to Authentication Service
   - Handshake Protocol verifies identity and device
   - Neural Signature verifies biometrics for high-level agents
   - Session Manager creates secure token and session
   - Agent profile retrieved and clearance level verified

2. **Query Processing Flow**
   - Agent submits query through secure interface
   - Query processed by NLP Engine for intent and keywords
   - Rules Matcher identifies applicable rules from framework
   - Clearance Level Checker verifies authorization
   - Query passed to Advanced RAG Layer for retrieval

3. **Advanced RAG Flow**
   - Vector Store performs embedding-based similarity search
   - Knowledge Graph traverses semantic connections between concepts
   - Hybrid Retrieval Engine combines results with security filtering
   - Results returned to Response Generation Layer

4. **Response Generation Flow**
   - Response Generator formats information based on agent level
   - Greeting Formatter adds level-specific greeting
   - Response Formatter applies rule-specific formatting
   - Information Scrambler applies required obfuscation for security
   - Formatted response passed to Encryption Layer

5. **Encryption Flow**
   - LCC System applies layered encryption
   - Quantum Hashing creates secure digest
   - OTP Generator applies one-time pad
   - Ghost-Step Algorithm removes digital fingerprints
   - Encrypted response returned to agent

6. **Security Monitoring Flow**
   - All operations logged in tamper-proof audit trail
   - Mosaic Anomaly Detection analyzes patterns
   - Query Pattern Analyzer looks for suspicious sequences
   - Threat Assessment evaluates potential security risks
   - Protocol Zeta-5 can terminate sessions if critical breach detected

This layered, security-first architecture ensures that all operations are authenticated, authorized, encrypted, monitored, and audited at every step.

---

## Advanced RAG Layer

The Advanced RAG (Retrieval-Augmented Generation) Layer is the core intelligence component of Project SHADOW, responsible for securely retrieving relevant information based on agent queries while maintaining strict security boundaries.

### Core Components

#### Vector Store (`vector_store_builder.py`)

The Vector Store component manages embedded representations of rules, trigger phrases, and responses using the FAISS (Facebook AI Similarity Search) library. It enables fast similarity-based retrieval of relevant information.

Key features:
- Embedding generation using state-of-the-art language models
- Efficient indexing for sub-millisecond retrieval
- Document chunking for granular retrieval
- Security-aware search filtering

```python
# Example of vector store initialization
vector_store = VectorStoreBuilder(
    rules_file_path="data.json",
    vector_store_path="./vector_store",
    embedding_model="sentence-transformers/all-mpnet-base-v2",
    enable_rule_chunking=True
)
```

#### Knowledge Graph (`knowledge_graph_builder.py`)

The Knowledge Graph organizes intelligence data in a semantic network of connected entities, concepts, and rules. It enables path-based retrieval and reasoning about relationships between different pieces of information.

Key features:
- Graph-based representation of intelligence data
- Multi-type relationships between entities
- Path-based traversal algorithms
- Semantic connection discovery

```python
# Example of knowledge graph initialization
knowledge_graph = KnowledgeGraphBuilder(
    rules_file_path="data.json",
    graph_output_path="./graph_store/graph.json",
    embedding_model="sentence-transformers/all-mpnet-base-v2"
)
```

#### Hybrid Retrieval Engine (`hybrid_retrieval_engine.py`)

The Hybrid Retrieval Engine combines multiple retrieval methods to deliver the most relevant and secure responses based on agent queries and clearance levels.

Key features:
- Multi-strategy retrieval combining vector, graph, and keyword methods
- Adaptive weighting based on query and security context
- Clearance-level filtering
- Special directive handling

```python
# Example of hybrid retrieval initialization
retrieval_engine = HybridRetrievalEngine(
    vector_store_path="./vector_store",
    graph_db_path="./graph_store",
    rules_file_path="data.json",
    embedding_dimension=768
)
```

### Retrieval Methodologies

The Advanced RAG Layer employs three primary retrieval methodologies that work together to provide comprehensive and contextually relevant results:

#### Vector Similarity

Vector similarity retrieval converts queries and documents into high-dimensional embeddings and finds matches based on semantic similarity.

Process:
1. Convert query to embedding vector using language model
2. Search FAISS index for most similar rule embeddings
3. Calculate cosine similarity scores
4. Return top matches above similarity threshold
5. Filter based on agent clearance level

This approach excels at finding semantically similar content even when the exact keywords don't match.

#### Graph Traversal

Graph traversal leverages the knowledge graph to find connected information and discover relationships that might not be apparent through direct similarity.

Process:
1. Identify entry points in graph based on query terms
2. Traverse the graph following relationship edges
3. Apply path scoring based on relation types and edge weights
4. Collect rules connected through semantic paths
5. Filter based on agent clearance level

This approach is particularly effective for finding related concepts and building contextual understanding.

#### Keyword Matching

Keyword matching serves as a reliable fallback when vector or graph methods don't produce sufficient results.

Process:
1. Extract key terms from the query
2. Match against rule trigger phrases
3. Calculate match scores based on exact and partial matches
4. Filter based on agent clearance level

This straightforward approach ensures basic query understanding even in edge cases.

### Security Integration

The Advanced RAG Layer incorporates security at every step of the retrieval process:

1. **Pre-Retrieval Security**
   - Query analysis for security implications
   - Agent clearance verification
   - Session validity confirmation

2. **During-Retrieval Security**
   - Rule-level clearance filtering
   - Security-aware scoring adjustments
   - Sensitive combination detection

3. **Post-Retrieval Security**
   - Mosaic pattern analysis
   - Response content filtering
   - Information scrambling when required

4. **Continuous Monitoring**
   - Query pattern analysis
   - Anomaly detection
   - Security event logging

This multi-layered security approach ensures that even the most sophisticated attempts to circumvent security measures will be detected and prevented.

---

## Vector Store Implementation

The Vector Store provides the embedding-based similarity search capability for Project SHADOW, enabling semantic understanding and retrieval of intelligence data.

### Embedding Generation

The Vector Store uses state-of-the-art language models to generate embeddings that capture the semantic meaning of rules, trigger phrases, and responses.

#### Embedding Model Selection

The system uses the `sentence-transformers/all-mpnet-base-v2` model for generating embeddings, chosen for its balance of performance, accuracy, and efficiency. This model produces 768-dimensional embeddings that effectively capture semantic relationships between texts.

Alternative models supported include:
- `sentence-transformers/multi-qa-mpnet-base-dot-v1` (optimized for question-answering)
- `sentence-transformers/paraphrase-multilingual-mpnet-base-v2` (for multilingual support)
- Custom fine-tuned models (for domain-specific applications)

#### Document Preparation

Before embedding generation, documents are prepared to maximize retrieval effectiveness:

1. **Rule Decomposition**: Each rule is broken down into individual components:
   - Trigger phrases (embedded separately)
   - Response instructions
   - Response text (if available)
   - Combined rule text

2. **Chunking Strategy**: Longer texts are chunked into smaller segments to:
   - Improve retrieval granularity
   - Enhance semantic focus
   - Optimize vector search performance

3. **Metadata Enrichment**: Each document chunk is enriched with metadata:
   - Rule ID
   - Required clearance level
   - Document type (trigger_phrase, rule, etc.)
   - Chunk ID (if applicable)

```python
# Example document preparation
documents = []
for rule in self.rules:
    # Create document for each trigger phrase
    for phrase in rule.get("trigger_phrases", []):
        documents.append({
            "type": "trigger_phrase",
            "rule_id": rule["id"],
            "text": phrase,
            "required_level": rule.get("required_level")
        })
    
    # Create document for the entire rule
    combined_text = f"Rule {rule_id}: {' '.join(rule.get('trigger_phrases', []))}"
    documents.append({
        "type": "rule",
        "rule_id": rule["id"],
        "text": combined_text,
        "required_level": rule.get("required_level")
    })
```

### Indexing Strategies

The Vector Store uses FAISS (Facebook AI Similarity Search) for efficient indexing and retrieval of high-dimensional vectors.

#### Index Types

Different index types are used based on collection size and performance requirements:

1. **Flat Index (IndexFlatIP)**:
   - Used for smaller collections (< 100K vectors)
   - Provides exact nearest neighbor search
   - Optimized for inner product (cosine similarity)

2. **IVF Index (IndexIVFFlat)**:
   - Used for medium collections (100K - 1M vectors)
   - Approximate nearest neighbor search with inverted file structure
   - Configurable tradeoff between speed and accuracy

3. **HNSW Index (IndexHNSWFlat)**:
   - Used for large collections (> 1M vectors)
   - Hierarchical Navigable Small World graph structure
   - Excellent balance of speed and recall

#### Normalization

All vectors are L2-normalized before indexing to enable cosine similarity search using inner product, which is more efficient in FAISS:

```python
# Normalize embeddings for cosine similarity
faiss.normalize_L2(embeddings)
```

#### Index Persistence

The Vector Store saves and loads indexes and metadata to disk:

1. **Index File**: `{vector_store_path}/index.faiss`
2. **Index to ID Mapping**: `{vector_store_path}/index_to_id.json`
3. **Document Store**: `{vector_store_path}/document_store.json`

This persistence strategy allows the system to restart without rebuilding the entire vector store, improving startup performance.

### Search Optimization

The Vector Store implements several optimizations to enhance search quality and performance:

#### Query Preprocessing

Before searching, queries undergo similar preprocessing as documents:

1. Embedding generation using the same model
2. L2 normalization for cosine similarity
3. Optional query expansion for broader matches

#### Search Parameters

Search parameters are dynamically adjusted based on context:

1. **k value**: Number of results to retrieve (adjusted based on retrieval mode)
2. **Similarity threshold**: Minimum similarity score to consider a match (0.65 by default)
3. **nprobe** (for IVF indexes): Number of clusters to search (affects recall vs. speed)

#### Context-Aware Search

The search process incorporates context awareness:

1. **Clearance filtering**: Only returns results appropriate for agent's clearance level
2. **Retrieval mode adaptation**:
   - "precision" mode prioritizes exact matches
   - "recall" mode retrieves more potential matches
   - "balanced" mode (default) provides middle ground

#### Post-Processing

After vector search, results undergo post-processing:

1. **Deduplication**: Removing duplicate rules from different chunks
2. **Score normalization**: Adjusting scores for consistent interpretation
3. **Metadata enrichment**: Adding rule details to search results

This multi-faceted optimization approach ensures that vector search is both accurate and efficient, even with large collections of intelligence data.

---

## Knowledge Graph System

The Knowledge Graph System provides a semantic network representation of intelligence data, enabling relationship-based retrieval and reasoning.

### Graph Structure

The Knowledge Graph uses a directed property graph model implemented with NetworkX, where nodes represent entities and edges represent relationships between them.

#### Node Types

The graph contains several types of nodes:

1. **Rule Nodes**: 
   - Represent individual rules from the framework
   - ID format: `rule_{rule_id}`
   - Properties: rule_id, required_level, response_instruction, has_response_text

2. **Phrase Nodes**:
   - Represent trigger phrases that activate rules
   - ID format: `phrase_{phrase_text}`
   - Properties: text

3. **Clearance Level Nodes**:
   - Represent agent clearance levels (1-5)
   - ID format: `level_{level_number}`
   - Properties: level, description

4. **Category Nodes**:
   - Represent groupings of related rules
   - ID format: `category_{name}`
   - Properties: description, importance

5. **Special Directive Nodes**:
   - Represent special codewords or directives
   - ID format: `special_directives`
   - Properties: description

#### Node Properties

Each node type has specific properties that facilitate retrieval and analysis:

```python
# Example of rule node creation
self.knowledge_graph.add_node(
    f"rule_{rule_id}",
    type="rule",
    rule_id=rule_id,
    required_level=required_level,
    response_instruction=rule.get("response_instruction", ""),
    has_response_text=bool(rule.get("response_text"))
)
```

### Relationship Types

The Knowledge Graph uses typed edges to represent different kinds of relationships between nodes:

1. **Triggers** (phrase → rule):
   - Indicates that a phrase triggers a specific rule
   - Properties: weight (strength of association)

2. **Has Access** (level → rule):
   - Indicates which clearance level can access a rule
   - Properties: weight (always 1.0)

3. **Semantic** (rule → rule):
   - Indicates that two rules are semantically related
   - Properties: weight (similarity score), type="semantic"

4. **References** (rule → rule):
   - Indicates that one rule explicitly references another
   - Properties: weight (importance of reference), type="references"

5. **Contains** (category → rule):
   - Indicates that a rule belongs to a category
   - Properties: weight (degree of membership)

#### Edge Weighting

Edges in the graph are weighted to reflect the strength of relationships:

1. **Trigger weights**: Always 1.0, indicating direct connection
2. **Semantic weights**: 0.1 to 1.0, based on computed similarity
3. **Reference weights**: 0.9, indicating strong connection
4. **Containment weights**: 1.0, indicating full membership

These weights influence traversal algorithms and result ranking.

### Traversal Algorithms

The Knowledge Graph implements several traversal algorithms for different query scenarios:

#### 1. Direct Phrase Matching

This algorithm directly matches query terms to phrase nodes:

```python
# Find matching phrase nodes
matched_nodes = set()
for token in query_tokens:
    for node, attrs in self.knowledge_graph.nodes(data=True):
        if attrs.get("type") == "phrase" and token.lower() in attrs.get("text", "").lower():
            matched_nodes.add(node)
```

#### 2. Recursive Path Exploration

This algorithm recursively explores paths from matched nodes:

```python
def traverse_graph(start_node, depth=0, visited=None, path_quality=1.0):
    if visited is None:
        visited = set()
    
    if depth >= self.graph_depth_limit or start_node in visited:
        return {}
    
    visited.add(start_node)
    rule_scores = {}
    
    # Process outgoing edges
    for target in self.knowledge_graph.successors(start_node):
        edge_data = self.knowledge_graph.get_edge_data(start_node, target)
        edge_weight = edge_data.get("weight", 0.8)
        
        # Apply path quality degradation
        new_quality = path_quality * edge_weight
        
        # Collect rules and continue traversal
        if target.startswith("rule_"):
            rule_id = int(target.split("_")[1])
            rule_scores[rule_id] = new_quality
        
        # Continue traversal recursively
        deeper_scores = traverse_graph(target, depth + 1, visited, new_quality)
        for rule_id, score in deeper_scores.items():
            rule_scores[rule_id] = max(rule_scores.get(rule_id, 0), score)
    
    return rule_scores
```

#### 3. Clearance-Based Filtering

This algorithm ensures only rules matching the agent's clearance are returned:

```python
# Filter rules by clearance level
filtered_rules = {}
for rule_id, score in rule_scores.items():
    rule = next((r for r in self.rules if r["id"] == rule_id), None)
    if rule:
        required_level = rule.get("required_level")
        if required_level == "any" or int(required_level) <= agent_level:
            filtered_rules[rule_id] = score
```

#### 4. Multi-Path Merging

This algorithm combines scores from multiple paths to the same rule:

```python
# Merge scores from multiple paths
merged_scores = {}
for start_node in matched_nodes:
    path_scores = traverse_graph(start_node)
    for rule_id, score in path_scores.items():
        if rule_id not in merged_scores:
            merged_scores[rule_id] = 0
        merged_scores[rule_id] = max(merged_scores[rule_id], score)
```

These traversal algorithms enable sophisticated pattern matching and relationship discovery that complement the vector-based similarity search, providing a more comprehensive understanding of the intelligence data.

---

## Hybrid Retrieval Engine

The Hybrid Retrieval Engine combines multiple retrieval methodologies to provide optimal results for agent queries, balancing relevance, context, and security considerations.

### Retrieval Modes

The Hybrid Retrieval Engine supports different retrieval modes that can be selected based on query context and security requirements:

#### Precision Mode

Precision mode prioritizes exact matches and high confidence results, reducing the risk of returning irrelevant information.

- Vector search parameters: higher similarity threshold (0.75)
- Graph search parameters: lower depth limit (2), stricter path quality threshold
- Result scoring: higher weight to exact matches (0.7 vector, 0.2 graph, 0.1 keyword)
- Results prioritized: fewer results with higher confidence

Use cases:
- Security-critical operations
- Tactical information retrieval
- When accuracy is paramount

#### Balanced Mode (Default)

Balanced mode provides a middle ground between precision and recall, suitable for most standard queries.

- Vector search parameters: standard similarity threshold (0.65)
- Graph search parameters: standard depth limit (3), default path quality threshold
- Result scoring: even distribution (0.6 vector, 0.3 graph, 0.1 keyword)
- Results prioritized: mix of high confidence and exploratory results

Use cases:
- Standard intelligence queries
- General information requests
- Routine operations

#### Recall Mode

Recall mode maximizes the retrieval of potentially relevant information, casting a wider net.

- Vector search parameters: lower similarity threshold (0.55)
- Graph search parameters: higher depth limit (4), relaxed path quality threshold
- Result scoring: emphasis on breadth (0.4 vector, 0.4 graph, 0.2 keyword)
- Results prioritized: more results with varied confidence

Use cases:
- Exploratory research
- When missing information is costly
- Complex queries requiring multiple information pieces

### Scoring Mechanisms

The Hybrid Retrieval Engine uses a sophisticated multi-factor scoring system to rank and combine results from different retrieval methods:

#### 1. Method-Specific Scoring

Each retrieval method provides its own relevance scores:

**Vector Similarity Scoring:**
- Raw cosine similarity score (0-1 scale)
- Position bonus for top results
- Length normalization for fairness across document sizes

**Graph Traversal Scoring:**
- Path quality score based on edge weights
- Path length penalty (longer paths score lower)
- Node type weighting (direct rule matches score higher than category-based matches)

**Keyword Matching Scoring:**
- Exact match scoring (1.0 for exact phrase matches)
- Partial match scoring (proportion of matched words)
- Position weighting (earlier matches in query score higher)

#### 2. Weighted Combination

The scores from different methods are combined using a weighted approach:

```python
# Update rule scores from each method
def update_scores(matches, weight, method):
    for i, match in enumerate(matches):
        rule_id = match.rule_id
        
        # Adjust score based on position
        position_factor = 1.0 / (i + 1)  # Higher rank = higher score
        adjusted_score = match.match_score * position_factor
        
        if rule_id not in rule_scores:
            rule_scores[rule_id] = {
                "weighted_score": 0,
                "max_raw_score": 0,
                "methods": set(),
                "match": match,
                "confidence": 0
            }
        
        # Update weighted score
        rule_scores[rule_id]["weighted_score"] += adjusted_score * weight
        
        # Track methods and update confidence
        rule_scores[rule_id]["methods"].add(method)
        rule_scores[rule_id]["confidence"] = max(
            rule_scores[rule_id]["confidence"],
            match.confidence * weight
        )
```

#### 3. Multi-Method Bonus

Rules that appear in multiple retrieval methods receive a confidence boost:

```python
# Apply multi-method bonus
for rule_id, data in rule_scores.items():
    if len(data["methods"]) > 1:
        # Apply bonus for appearing in multiple methods
        method_count = len(data["methods"])
        data["weighted_score"] *= (1.0 + (method_count - 1) * 0.1)
```

#### 4. Security-Based Adjustment

Final scores are adjusted based on security considerations:

```python
# Apply security-based adjustments
if context.security_level == "critical":
    # In critical security mode, penalize rules close to clearance boundary
    for rule_id, data in rule_scores.items():
        match = data["match"]
        if match.required_level != "any" and int(match.required_level) == agent_level:
            # Reduce score for rules at the clearance boundary
            data["weighted_score"] *= 0.8
```

### Context Adaptation

The Hybrid Retrieval Engine adapts to query context through several mechanisms:

#### 1. Query Analysis

Each query is analyzed to optimize retrieval parameters:

```python
def enhance_retrieval_context(self, query_text, context):
    # Copy context to avoid modifying the original
    enhanced_context = RetrievalContext(**context.dict())
    
    # Analyze query complexity
    query_length = len(query_text.split())
    if query_length > 20:
        # Complex queries need precision
        enhanced_context.retrieval_mode = "precision"
    elif query_length < 5:
        # Simple queries need recall
        enhanced_context.retrieval_mode = "recall"
    
    # Check for time-sensitive patterns
    time_sensitive_phrases = ["urgent", "immediate", "emergency"]
    if any(phrase in query_text.lower() for phrase in time_sensitive_phrases):
        enhanced_context.security_level = "critical"
        
    return enhanced_context
```

#### 2. Session Context Utilization

The retrieval process incorporates session history and context:

- Recent queries influence result ranking
- Session security level affects filtering strictness
- Previous rule accesses inform traversal patterns

#### 3. Special Directive Handling

Special directives and codewords receive priority handling:

```python
def execute_special_directive(self, directive, context):
    directive_lower = directive.lower()
    
    # Check for direct matches with special directives
    for rule in self.rules:
        for phrase in rule.get("trigger_phrases", []):
            if phrase.lower() == directive_lower:
                # This is a direct match for a special directive
                if rule.get("response_text"):
                    return RuleMatch(
                        rule_id=rule["id"],
                        trigger_phrases=[phrase],
                        required_level=rule.get("required_level", "any"),
                        response_instruction=rule.get("response_instruction", ""),
                        response_text=rule.get("response_text", ""),
                        match_score=1.0,  # Perfect score for direct match
                        match_method="directive",
                        confidence=1.0
                    )
    
    return None
```

#### 4. Security-Level Responsiveness

The engine adjusts its behavior based on the current security level:

- **Standard**: Normal operation with balanced retrieval
- **Elevated**: Stricter filtering, preference for precise matches
- **Critical**: Maximum security, potential information scrambling

This adaptive approach ensures that the Hybrid Retrieval Engine responds appropriately to both the query content and the broader operational context, delivering optimal results while maintaining security boundaries.

---

## Security Framework

Project SHADOW implements a comprehensive security framework to protect sensitive intelligence data, enforce access controls, and detect potential security breaches.

### Clearance Level Management

The system implements a strict clearance level hierarchy that determines access to information:

#### Level Hierarchy

1. **Level 1 - Novice Operative (Shadow Footprint)**
   - Basic operational information
   - Training materials
   - Publicly acknowledged operations

2. **Level 2 - Tactical Specialist (Iron Claw)**
   - Field operation protocols
   - Asset management techniques
   - Limited tactical intelligence

3. **Level