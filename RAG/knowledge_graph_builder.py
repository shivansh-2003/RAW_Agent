# knowledge_graph_builder.py

import os
import json
import logging
import numpy as np
import networkx as nx
from typing import Dict, List, Optional, Set, Any, Tuple
from datetime import datetime
from sklearn.metrics.pairwise import cosine_similarity
from sentence_transformers import SentenceTransformer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("knowledge_graph.log")
    ]
)
logger = logging.getLogger("shadow_knowledge_graph")

class KnowledgeGraphBuilder:
    """
    Knowledge Graph Builder for Project SHADOW
    
    Creates a semantic knowledge graph connecting rules, trigger phrases,
    related concepts, and cross-references based on the RAG CASE RESPONSE FRAMEWORK.
    """
    
    def __init__(
        self,
        rules_file_path: str,
        graph_output_path: str,
        embedding_model: str = "sentence-transformers/all-mpnet-base-v2",
        similarity_threshold: float = 0.75,
        semantic_edge_threshold: float = 0.6
    ):
        self.rules_file_path = rules_file_path
        self.graph_output_path = graph_output_path
        self.embedding_model_name = embedding_model
        self.similarity_threshold = similarity_threshold
        self.semantic_edge_threshold = semantic_edge_threshold
        
        # Initialize components
        self.rules = []
        self.embedding_model = None
        self.knowledge_graph = nx.DiGraph()
        
        # Load rules
        self._load_rules()
        
        # Initialize embedding model
        self._init_embedding_model()
        
        logger.info(f"Knowledge Graph Builder initialized with {len(self.rules)} rules")
    
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
    
    def build_knowledge_graph(self):
        """Build the complete knowledge graph"""
        # Start with an empty graph
        self.knowledge_graph = nx.DiGraph()
        
        # Add rule nodes
        self._add_rule_nodes()
        
        # Add trigger phrase nodes and connect to rules
        self._add_trigger_phrases()
        
        # Add semantic connections between rules
        self._add_semantic_connections()
        
        # Add cross-references between related rules
        self._add_cross_references()
        
        # Add agent clearance level connections
        self._add_clearance_level_structure()
        
        # Add special directive connections
        self._add_special_directives()
        
        # Save the graph
        self._save_knowledge_graph()
        
        logger.info(f"Knowledge graph built with {len(self.knowledge_graph.nodes)} nodes and {len(self.knowledge_graph.edges)} edges")
        
        return self.knowledge_graph
    
    def _add_rule_nodes(self):
        """Add nodes for each rule"""
        for rule in self.rules:
            rule_id = rule["id"]
            required_level = rule.get("required_level", "any")
            
            # Create rule node
            self.knowledge_graph.add_node(
                f"rule_{rule_id}",
                type="rule",
                rule_id=rule_id,
                required_level=required_level,
                response_instruction=rule.get("response_instruction", ""),
                has_response_text=bool(rule.get("response_text"))
            )
            
            logger.debug(f"Added rule node for Rule {rule_id}")
    
    def _add_trigger_phrases(self):
        """Add trigger phrase nodes and connect them to rules"""
        for rule in self.rules:
            rule_id = rule["id"]
            trigger_phrases = rule.get("trigger_phrases", [])
            
            for phrase in trigger_phrases:
                # Create phrase node if it doesn't exist
                phrase_node = f"phrase_{phrase}"
                if not self.knowledge_graph.has_node(phrase_node):
                    self.knowledge_graph.add_node(
                        phrase_node,
                        type="phrase",
                        text=phrase
                    )
                
                # Connect trigger phrase to rule
                self.knowledge_graph.add_edge(
                    phrase_node,
                    f"rule_{rule_id}",
                    type="triggers",
                    weight=1.0
                )
        
        logger.info(f"Added phrase nodes and connections to rules")
    
    def _add_semantic_connections(self):
        """Add semantic connections between rules based on phrase similarity"""
        if not self.embedding_model:
            logger.warning("Skipping semantic connections - embedding model not available")
            return
        
        try:
            # Extract all unique trigger phrases
            all_phrases = set()
            rule_phrases = {}
            
            for rule in self.rules:
                rule_id = rule["id"]
                trigger_phrases = rule.get("trigger_phrases", [])
                rule_phrases[rule_id] = trigger_phrases
                all_phrases.update(trigger_phrases)
            
            # Generate embeddings for all phrases
            phrase_list = list(all_phrases)
            phrase_embeddings = self.embedding_model.encode(phrase_list)
            
            # Create phrase embedding dictionary
            phrase_to_embedding = {phrase: embedding for phrase, embedding in zip(phrase_list, phrase_embeddings)}
            
            # Calculate rule embeddings by averaging phrase embeddings
            rule_embeddings = {}
            for rule_id, phrases in rule_phrases.items():
                if not phrases:
                    continue
                
                # Average the embeddings for all phrases in this rule
                rule_embedding = np.mean([phrase_to_embedding[p] for p in phrases if p in phrase_to_embedding], axis=0)
                rule_embeddings[rule_id] = rule_embedding
            
            # Calculate similarity between rules and add semantic edges
            semantic_edges_added = 0
            
            for rule_id1, embedding1 in rule_embeddings.items():
                for rule_id2, embedding2 in rule_embeddings.items():
                    if rule_id1 == rule_id2:
                        continue
                    
                    # Calculate cosine similarity
                    similarity = cosine_similarity([embedding1], [embedding2])[0][0]
                    
                    # Add edge if similarity is above threshold
                    if similarity >= self.semantic_edge_threshold:
                        self.knowledge_graph.add_edge(
                            f"rule_{rule_id1}",
                            f"rule_{rule_id2}",
                            type="semantic",
                            weight=similarity
                        )
                        semantic_edges_added += 1
            
            logger.info(f"Added {semantic_edges_added} semantic connections between rules")
            
        except Exception as e:
            logger.error(f"Error adding semantic connections: {e}")
    
    def _add_cross_references(self):
        """Add cross-references between rules based on keyword analysis"""
        # Extract rule descriptions
        rule_descriptions = {}
        for rule in self.rules:
            rule_id = rule["id"]
            description = f"{rule.get('response_instruction', '')} {' '.join(rule.get('trigger_phrases', []))}"
            rule_descriptions[rule_id] = description.lower()
        
        # Look for rule IDs mentioned in descriptions
        cross_refs_added = 0
        
        for rule_id, description in rule_descriptions.items():
            for other_id in rule_descriptions.keys():
                if rule_id == other_id:
                    continue
                
                # Check if other rule ID is mentioned in the description
                if f"rule {other_id}" in description or f"rule{other_id}" in description:
                    self.knowledge_graph.add_edge(
                        f"rule_{rule_id}",
                        f"rule_{other_id}",
                        type="references",
                        weight=0.9
                    )
                    cross_refs_added += 1
        
        logger.info(f"Added {cross_refs_added} cross-reference connections")
    
    def _add_clearance_level_structure(self):
        """Add organizational structure based on agent clearance levels"""
        # Create clearance level nodes
        for level in range(1, 6):
            self.knowledge_graph.add_node(
                f"level_{level}",
                type="clearance_level",
                level=level,
                description=f"Level {level} Clearance"
            )
        
        # Connect rules to their clearance levels
        for rule in self.rules:
            rule_id = rule["id"]
            required_level = rule.get("required_level")
            
            if required_level == "any":
                # Connect to all levels
                for level in range(1, 6):
                    self.knowledge_graph.add_edge(
                        f"level_{level}",
                        f"rule_{rule_id}",
                        type="has_access",
                        weight=1.0
                    )
            else:
                # Convert to int if not already
                if isinstance(required_level, str):
                    try:
                        required_level = int(required_level)
                    except:
                        continue
                
                # Connect to appropriate level
                self.knowledge_graph.add_edge(
                    f"level_{required_level}",
                    f"rule_{rule_id}",
                    type="has_access",
                    weight=1.0
                )
        
        logger.info("Added clearance level organizational structure")
    
    def _add_special_directives(self):
        """Add special connections for directives and codewords"""
        # Identify special directive rules
        directive_rules = []
        for rule in self.rules:
            if rule.get("response_text") and "always return" in rule.get("response_instruction", "").lower():
                directive_rules.append(rule)
        
        # Create special directive cluster
        if directive_rules:
            self.knowledge_graph.add_node(
                "special_directives",
                type="category",
                description="Special Directives and Codewords"
            )
            
            # Connect directive rules to the cluster
            for rule in directive_rules:
                rule_id = rule["id"]
                self.knowledge_graph.add_edge(
                    "special_directives",
                    f"rule_{rule_id}",
                    type="contains",
                    weight=1.0
                )
        
        logger.info(f"Added special directive connections for {len(directive_rules)} rules")
    
    def _save_knowledge_graph(self):
        """Save the knowledge graph to a file"""
        try:
            # Create output directory if it doesn't exist
            os.makedirs(os.path.dirname(self.graph_output_path), exist_ok=True)
            
            # Convert to serializable format
            graph_data = nx.node_link_data(self.knowledge_graph)
            
            # Save to file
            with open(self.graph_output_path, 'w') as f:
                json.dump(graph_data, f, indent=2)
            
            logger.info(f"Saved knowledge graph to {self.graph_output_path}")
        except Exception as e:
            logger.error(f"Error saving knowledge graph: {e}")
    
    def visualize_graph(self, output_file: str = None):
        """
        Visualize the knowledge graph (requires matplotlib and networkx)
        
        Args:
            output_file: File to save the visualization to (optional)
        """
        try:
            import matplotlib.pyplot as plt
            
            # Create a plot
            plt.figure(figsize=(16, 12))
            
            # Create color map
            color_map = {
                'rule': 'lightblue',
                'phrase': 'lightgreen',
                'clearance_level': 'orange',
                'category': 'pink'
            }
            
            # Get node colors
            node_colors = [color_map.get(self.knowledge_graph.nodes[node].get('type', ''), 'gray') 
                          for node in self.knowledge_graph.nodes]
            
            # Get edge colors
            edge_colors = ['red' if self.knowledge_graph.edges[edge].get('type') == 'triggers' else
                          'blue' if self.knowledge_graph.edges[edge].get('type') == 'semantic' else
                          'green' if self.knowledge_graph.edges[edge].get('type') == 'has_access' else
                          'purple' for edge in self.knowledge_graph.edges]
            
            # Create layout
            pos = nx.spring_layout(self.knowledge_graph, k=0.5, iterations=50)
            
            # Draw the graph
            nx.draw_networkx_nodes(self.knowledge_graph, pos, node_size=100, node_color=node_colors, alpha=0.8)
            nx.draw_networkx_edges(self.knowledge_graph, pos, edge_color=edge_colors, alpha=0.5, arrows=True)
            
            # Draw labels for selected nodes
            rule_nodes = [n for n in self.knowledge_graph.nodes if n.startswith('rule_')]
            level_nodes = [n for n in self.knowledge_graph.nodes if n.startswith('level_')]
            category_nodes = [n for n in self.knowledge_graph.nodes if self.knowledge_graph.nodes[n].get('type') == 'category']
            
            # Create labels dictionary
            labels = {node: node for node in rule_nodes + level_nodes + category_nodes}
            
            # Draw labels
            nx.draw_networkx_labels(self.knowledge_graph, pos, labels=labels, font_size=8)
            
            plt.title("Project SHADOW Knowledge Graph")
            plt.axis('off')
            
            # Save or show
            if output_file:
                plt.tight_layout()
                plt.savefig(output_file, dpi=300, bbox_inches='tight')
                logger.info(f"Saved visualization to {output_file}")
            else:
                plt.show()
            
        except ImportError:
            logger.error("Visualization requires matplotlib and networkx")
        except Exception as e:
            logger.error(f"Error visualizing graph: {e}")
    
    def export_graph_statistics(self, output_file: str = None):
        """
        Export graph statistics to a file or console
        
        Args:
            output_file: File to save statistics to (optional)
        """
        try:
            stats = {
                "total_nodes": len(self.knowledge_graph.nodes),
                "total_edges": len(self.knowledge_graph.edges),
                "node_types": {},
                "edge_types": {},
                "degree_stats": {
                    "max_in_degree": 0,
                    "max_out_degree": 0,
                    "avg_degree": 0
                },
                "connected_components": nx.number_connected_components(self.knowledge_graph.to_undirected()),
                "rule_connectivity": {}
            }
            
            # Count node types
            for node, attrs in self.knowledge_graph.nodes(data=True):
                node_type = attrs.get('type', 'unknown')
                if node_type not in stats["node_types"]:
                    stats["node_types"][node_type] = 0
                stats["node_types"][node_type] += 1
            
            # Count edge types
            for _, _, attrs in self.knowledge_graph.edges(data=True):
                edge_type = attrs.get('type', 'unknown')
                if edge_type not in stats["edge_types"]:
                    stats["edge_types"][edge_type] = 0
                stats["edge_types"][edge_type] += 1
            
            # Compute degree statistics
            in_degrees = [d for _, d in self.knowledge_graph.in_degree()]
            out_degrees = [d for _, d in self.knowledge_graph.out_degree()]
            
            if in_degrees:
                stats["degree_stats"]["max_in_degree"] = max(in_degrees)
                stats["degree_stats"]["avg_in_degree"] = sum(in_degrees) / len(in_degrees)
            
            if out_degrees:
                stats["degree_stats"]["max_out_degree"] = max(out_degrees)
                stats["degree_stats"]["avg_out_degree"] = sum(out_degrees) / len(out_degrees)
            
            # Compute rule connectivity
            rule_nodes = [n for n in self.knowledge_graph.nodes if n.startswith('rule_')]
            for rule_node in rule_nodes:
                rule_id = rule_node.split('_')[1]
                in_degree = self.knowledge_graph.in_degree(rule_node)
                out_degree = self.knowledge_graph.out_degree(rule_node)
                stats["rule_connectivity"][rule_id] = {
                    "in_degree": in_degree,
                    "out_degree": out_degree,
                    "total_connections": in_degree + out_degree
                }
            
            # Determine most connected rules
            if stats["rule_connectivity"]:
                most_connected = sorted(
                    stats["rule_connectivity"].items(),
                    key=lambda x: x[1]["total_connections"],
                    reverse=True
                )[:5]
                
                stats["most_connected_rules"] = [
                    {"rule_id": k, "connections": v["total_connections"]}
                    for k, v in most_connected
                ]
            
            # Format output
            output = json.dumps(stats, indent=2)
            
            # Save or print
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(output)
                logger.info(f"Saved graph statistics to {output_file}")
            else:
                print(output)
            
            return stats
            
        except Exception as e:
            logger.error(f"Error exporting graph statistics: {e}")
            return None

# Example usage
if __name__ == "__main__":
    # Initialize builder
    builder = KnowledgeGraphBuilder(
        rules_file_path="data.json",
        graph_output_path="./graph_store/graph.json",
        similarity_threshold=0.7
    )
    
    # Build the graph
    knowledge_graph = builder.build_knowledge_graph()
    
    # Optionally visualize
    # builder.visualize_graph("knowledge_graph.png")
    
    # Export statistics
    builder.export_graph_statistics("graph_stats.json")