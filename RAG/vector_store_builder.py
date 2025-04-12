# vector_store_builder.py

import os
import json
import logging
import numpy as np
import faiss
from typing import Dict, List, Optional, Any, Tuple
from sentence_transformers import SentenceTransformer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("vector_store.log")
    ]
)
logger = logging.getLogger("shadow_vector_store")

class VectorStoreBuilder:
    """
    Vector Store Builder for Project SHADOW
    
    Creates a FAISS vector store for efficient similarity search across
    rules, trigger phrases, and response instructions.
    """
    
    def __init__(
        self,
        rules_file_path: str,
        vector_store_path: str,
        embedding_model: str = "sentence-transformers/all-mpnet-base-v2",
        enable_rule_chunking: bool = True,
        chunk_size: int = 160
    ):
        self.rules_file_path = rules_file_path
        self.vector_store_path = vector_store_path
        self.embedding_model_name = embedding_model
        self.enable_rule_chunking = enable_rule_chunking
        self.chunk_size = chunk_size
        
        # Initialize components
        self.rules = []
        self.embedding_model = None
        self.index = None
        self.document_store = {}
        self.index_to_id_map = {}
        
        # Load rules
        self._load_rules()
        
        # Initialize embedding model
        self._init_embedding_model()
        
        logger.info(f"Vector Store Builder initialized with {len(self.rules)} rules")
    
    def _load_rules(self):
        """Load rules from the JSON file"""
        try:
            with open(self.rules_file_path, 'r') as f:
                data = json.load(f)
                self.rules = data.get('rules', [])
                
            logger.info(f"Loaded {len(self.rules)} rules from {self.rules_file_path}")
        except Exception as e:
            logger.error(f"Error loading rules: {e}")
            self.rules = []
    
    def _init_embedding_model(self):
        """Initialize the embedding model"""
        try:
            self.embedding_model = SentenceTransformer(self.embedding_model_name)
            logger.info(f"Initialized embedding model: {self.embedding_model_name}")
        except Exception as e:
            logger.error(f"Error initializing embedding model: {e}")
            self.embedding_model = None
    
    def build_vector_store(self):
        """Build the complete vector store"""
        if not self.embedding_model:
            logger.error("Cannot build vector store: embedding model not initialized")
            return None
        
        try:
            # Prepare documents for embedding
            documents = self._prepare_documents()
            logger.info(f"Prepared {len(documents)} documents for embedding")
            
            # Generate embeddings
            embeddings, doc_ids = self._generate_embeddings(documents)
            logger.info(f"Generated {len(embeddings)} embeddings")
            
            # Create FAISS index
            self.index = self._create_faiss_index(embeddings)
            
            # Create index to ID mapping
            self.index_to_id_map = {str(i): doc_ids[i] for i in range(len(doc_ids))}
            
            # Save the vector store
            self._save_vector_store()
            
            logger.info(f"Vector store built successfully with {len(embeddings)} vectors")
            
            return self.index
        except Exception as e:
            logger.error(f"Error building vector store: {e}")
            return None
    
    def _prepare_documents(self) -> List[Dict[str, Any]]:
        """Prepare documents for embedding"""
        documents = []
        
        for rule in self.rules:
            rule_id = rule["id"]
            trigger_phrases = rule.get("trigger_phrases", [])
            response_instruction = rule.get("response_instruction", "")
            response_text = rule.get("response_text", "")
            required_level = rule.get("required_level", "any")
            
            # Create document for each trigger phrase
            for phrase in trigger_phrases:
                doc = {
                    "type": "trigger_phrase",
                    "rule_id": rule_id,
                    "text": phrase,
                    "required_level": required_level
                }
                documents.append(doc)
            
            # Create document for response instruction
            if response_instruction:
                doc = {
                    "type": "response_instruction",
                    "rule_id": rule_id,
                    "text": response_instruction,
                    "required_level": required_level
                }
                documents.append(doc)
            
            # Create document for response text if available
            if response_text:
                doc = {
                    "type": "response_text",
                    "rule_id": rule_id,
                    "text": response_text,
                    "required_level": required_level
                }
                documents.append(doc)
            
            # Create combined document for the entire rule
            combined_text = f"Rule {rule_id}: "
            combined_text += f"Triggers: {', '.join(trigger_phrases)}. "
            if response_instruction:
                combined_text += f"Instruction: {response_instruction}. "
            if response_text:
                combined_text += f"Response: {response_text}"
            
            doc = {
                "type": "rule",
                "rule_id": rule_id,
                "text": combined_text,
                "required_level": required_level
            }
            documents.append(doc)
            
            # Optional: Create chunks for long texts
            if self.enable_rule_chunking and len(combined_text) > self.chunk_size * 1.5:
                chunks = self._create_chunks(combined_text, self.chunk_size)
                for i, chunk in enumerate(chunks):
                    doc = {
                        "type": "rule_chunk",
                        "rule_id": rule_id,
                        "chunk_id": i,
                        "text": chunk,
                        "required_level": required_level
                    }
                    documents.append(doc)
        
        # Save document store for retrieval
        self.document_store = {f"{doc['type']}_{doc['rule_id']}_{doc.get('chunk_id', 0)}": doc for doc in documents}
        
        return documents
    
    def _create_chunks(self, text: str, chunk_size: int) -> List[str]:
        """Split text into chunks for more granular retrieval"""
        # Simple chunking by words
        words = text.split()
        chunks = []
        
        for i in range(0, len(words), chunk_size):
            chunk = ' '.join(words[i:i+chunk_size])
            chunks.append(chunk)
        
        return chunks
    
    def _generate_embeddings(self, documents: List[Dict[str, Any]]) -> Tuple[np.ndarray, List[str]]:
        """Generate embeddings for documents"""
        texts = [doc["text"] for doc in documents]
        doc_ids = [f"{doc['type']}_{doc['rule_id']}_{doc.get('chunk_id', 0)}" for doc in documents]
        
        # Generate embeddings in batches
        batch_size = 32
        all_embeddings = []
        
        for i in range(0, len(texts), batch_size):
            batch_texts = texts[i:i+batch_size]
            batch_embeddings = self.embedding_model.encode(batch_texts)
            all_embeddings.append(batch_embeddings)
        
        # Combine batches
        embeddings = np.vstack(all_embeddings)
        
        # Normalize embeddings for cosine similarity
        faiss.normalize_L2(embeddings)
        
        return embeddings, doc_ids
    
    def _create_faiss_index(self, embeddings: np.ndarray) -> faiss.Index:
        """Create FAISS index for fast similarity search"""
        # Get dimensions
        d = embeddings.shape[1]
        
        # Create index - using Inner Product (IP) for cosine similarity with normalized vectors
        index = faiss.IndexFlatIP(d)
        
        # Add vectors to index
        index.add(embeddings)
        
        logger.info(f"Created FAISS index with {index.ntotal} vectors of dimension {d}")
        
        return index
    
    def _save_vector_store(self):
        """Save the vector store and metadata to disk"""
        try:
            # Create output directory if it doesn't exist
            os.makedirs(self.vector_store_path, exist_ok=True)
            
            # Save FAISS index
            index_path = f"{self.vector_store_path}/index.faiss"
            faiss.write_index(self.index, index_path)
            
            # Save index to ID mapping
            mapping_path = f"{self.vector_store_path}/index_to_id.json"
            with open(mapping_path, 'w') as f:
                json.dump(self.index_to_id_map, f)
            
            # Save document store
            doc_store_path = f"{self.vector_store_path}/document_store.json"
            with open(doc_store_path, 'w') as f:
                json.dump(self.document_store, f)
            
            logger.info(f"Saved vector store to {self.vector_store_path}")
        except Exception as e:
            logger.error(f"Error saving vector store: {e}")
    
    def query_vector_store(self, query_text: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Query the vector store for similar documents
        
        Args:
            query_text: Text to search for
            top_k: Number of results to return
            
        Returns:
            List of matching documents with scores
        """
        if not self.embedding_model or not self.index:
            logger.error("Cannot query: vector store not initialized")
            return []
        
        try:
            # Generate query embedding
            query_embedding = self.embedding_model.encode([query_text])[0]
            
            # Normalize the query vector for cosine similarity
            query_norm = np.linalg.norm(query_embedding)
            if query_norm > 0:
                query_embedding = query_embedding / query_norm
            
            # Reshape for FAISS
            query_vector = np.array([query_embedding]).astype(np.float32)
            
            # Query the index
            distances, indices = self.index.search(query_vector, top_k)
            
            # Process results
            results = []
            for i, (distance, idx) in enumerate(zip(distances[0], indices[0])):
                if idx >= 0:  # Valid index
                    doc_id = self.index_to_id_map.get(str(idx))
                    if doc_id and doc_id in self.document_store:
                        doc = self.document_store[doc_id]
                        results.append({
                            "score": float(distance),
                            "rule_id": doc["rule_id"],
                            "type": doc["type"],
                            "text": doc["text"],
                            "required_level": doc["required_level"]
                        })
            
            return results
        
        except Exception as e:
            logger.error(f"Error querying vector store: {e}")
            return []
    
    def load_existing_vector_store(self) -> bool:
        """Load an existing vector store from disk"""
        try:
            index_path = f"{self.vector_store_path}/index.faiss"
            mapping_path = f"{self.vector_store_path}/index_to_id.json"
            doc_store_path = f"{self.vector_store_path}/document_store.json"
            
            # Check if all files exist
            if not all(os.path.exists(p) for p in [index_path, mapping_path, doc_store_path]):
                logger.warning("Incomplete vector store found")
                return False
            
            # Load FAISS index
            self.index = faiss.read_index(index_path)
            
            # Load index to ID mapping
            with open(mapping_path, 'r') as f:
                self.index_to_id_map = json.load(f)
            
            # Load document store
            with open(doc_store_path, 'r') as f:
                self.document_store = json.load(f)
            
            logger.info(f"Loaded vector store with {self.index.ntotal} vectors")
            return True
            
        except Exception as e:
            logger.error(f"Error loading vector store: {e}")
            return False
    
    def update_vector_store(self, new_rules: List[Dict[str, Any]]) -> bool:
        """
        Update the vector store with new rules
        
        Args:
            new_rules: List of new rules to add
            
        Returns:
            Success status
        """
        if not self.embedding_model:
            logger.error("Cannot update: embedding model not initialized")
            return False
        
        try:
            # Prepare documents for the new rules
            original_rule_count = len(self.rules)
            self.rules.extend(new_rules)
            
            # Prepare only the new documents
            new_documents = []
            for rule in new_rules:
                rule_id = rule["id"]
                trigger_phrases = rule.get("trigger_phrases", [])
                response_instruction = rule.get("response_instruction", "")
                response_text = rule.get("response_text", "")
                required_level = rule.get("required_level", "any")
                
                # Add documents for this rule (similar to _prepare_documents)
                # Trigger phrases
                for phrase in trigger_phrases:
                    doc = {
                        "type": "trigger_phrase",
                        "rule_id": rule_id,
                        "text": phrase,
                        "required_level": required_level
                    }
                    new_documents.append(doc)
                
                # Response instruction
                if response_instruction:
                    doc = {
                        "type": "response_instruction",
                        "rule_id": rule_id,
                        "text": response_instruction,
                        "required_level": required_level
                    }
                    new_documents.append(doc)
                
                # Response text
                if response_text:
                    doc = {
                        "type": "response_text",
                        "rule_id": rule_id,
                        "text": response_text,
                        "required_level": required_level
                    }
                    new_documents.append(doc)
                
                # Combined document
                combined_text = f"Rule {rule_id}: "
                combined_text += f"Triggers: {', '.join(trigger_phrases)}. "
                if response_instruction:
                    combined_text += f"Instruction: {response_instruction}. "
                if response_text:
                    combined_text += f"Response: {response_text}"
                
                doc = {
                    "type": "rule",
                    "rule_id": rule_id,
                    "text": combined_text,
                    "required_level": required_level
                }
                new_documents.append(doc)
            
            # Generate embeddings for new documents
            new_embeddings, new_doc_ids = self._generate_embeddings(new_documents)
            
            # Update document store
            for i, doc_id in enumerate(new_doc_ids):
                self.document_store[doc_id] = new_documents[i]
            
            # Update index to ID mapping
            start_idx = self.index.ntotal
            for i, doc_id in enumerate(new_doc_ids):
                self.index_to_id_map[str(start_idx + i)] = doc_id
            
            # Add new vectors to index
            self.index.add(new_embeddings)
            
            # Save updated vector store
            self._save_vector_store()
            
            logger.info(f"Updated vector store with {len(new_rules)} new rules")
            return True
            
        except Exception as e:
            logger.error(f"Error updating vector store: {e}")
            return False

# Example usage
if __name__ == "__main__":
    # Initialize builder
    builder = VectorStoreBuilder(
        rules_file_path="data.json",
        vector_store_path="./vector_store",
        enable_rule_chunking=True
    )
    
    # Check for existing vector store
    if not builder.load_existing_vector_store():
        # Build new vector store
        builder.build_vector_store()
    
    # Test query
    results = builder.query_vector_store("What should I do if my mission is compromised?", top_k=3)
    for result in results:
        print(f"Rule {result['rule_id']} ({result['type']}): Score {result['score']:.4f}")
        print(f"  Level: {result['required_level']}")
        print(f"  Text: {result['text'][:100]}...")
        print()