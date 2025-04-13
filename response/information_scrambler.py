# information_scrambler.py

import logging
import random
import re
import hashlib
import base64
from typing import List, Dict, Any, Optional
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("information_scrambler.log")
    ]
)
logger = logging.getLogger("shadow_information_scrambler")

class InformationScrambler:
    """
    Information Scrambler for Project SHADOW
    
    This component applies various scrambling and obfuscation techniques to
    sensitive information as specified in the SECRET INFO MANUAL, including
    the Layered Cipher Code (LCC) system when required.
    """
    
    def __init__(self):
        """Initialize the Information Scrambler"""
        # Initialize key for simple encryption
        self.cipher_key = "SHADOW-KEY-23X7"
        
        # Initialize country names for substitution
        self.locations = [
            "Berlin", "Vienna", "Prague", "Warsaw", "Budapest", "Kyiv", 
            "Moscow", "Paris", "London", "Zurich", "Rome", "Madrid", 
            "Istanbul", "Cairo", "Riyadh", "Tehran", "Delhi", "Beijing",
            "Tokyo", "Seoul", "Bangkok", "Singapore", "Sydney", "Auckland",
            "Johannesburg", "Lagos", "Nairobi", "Buenos Aires", "Bogota", 
            "Lima", "Mexico City", "Washington", "New York", "Toronto"
        ]
        
        # Initialize operation codenames for substitution
        self.operation_names = [
            "Blue Phoenix", "Silver Wolf", "Dark Horizon", "Emerald Viper",
            "Crimson Eagle", "Phantom Veil", "White Lotus", "Black Diamond",
            "Golden Serpent", "Iron Tempest", "Shadow Blade", "Jade Dragon",
            "Purple Nexus", "Amber Ghost", "Cobalt Thunder", "Scarlet Mist",
            "Onyx Falcon", "Sapphire Moon", "Brass Sentinel", "Crystal Echo",
            "Ruby Silence", "Obsidian Dawn", "Azure Knight", "Emerald Tide"
        ]
        
        # Initialize agent codenames for substitution
        self.agent_names = [
            "Nightshade", "Ironclad", "Stormfront", "Wraith", "Sable",
            "Quicksilver", "Phantom", "Whisper", "Mirage", "Raven", 
            "Silhouette", "Echo", "Nomad", "Cipher", "Aegis", "Specter",
            "Valkyrie", "Fenris", "Chimera", "Druid", "Polaris", "Orion",
            "Helios", "Athena", "Ares", "Artemis", "Icarus", "Hermes"
        ]
        
        # Initialize random data for obfuscation
        self.random_data = [
            "orbital parameters", "tidal coefficients", "solar activity",
            "atmospheric conditions", "seismic readings", "electromagnetic fluctuations",
            "quantum state variance", "neural pattern alignment", "isotope degradation rate",
            "cryptographic seed entropy", "signal propagation patterns", "thermal imaging anomalies"
        ]
        
        logger.info("Information Scrambler initialized")
    
    def scramble_information(
        self, 
        text: str, 
        agent_level: int,
        encryption_level: str = "none"
    ) -> str:
        """
        Apply information scrambling based on agent level and encryption level
        
        Args:
            text: The text to scramble
            agent_level: The agent's clearance level
            encryption_level: Encryption level (none, basic, lcc)
            
        Returns:
            Scrambled text
        """
        if encryption_level == "none":
            # No scrambling needed
            return text
        
        # Apply different techniques based on encryption level
        if encryption_level == "lcc":
            # Apply Layered Cipher Code for highest security
            return self.apply_layered_cipher_code(text, agent_level)
        else:
            # Apply basic scrambling
            return self.apply_basic_scrambling(text, agent_level)
    
    def apply_basic_scrambling(self, text: str, agent_level: int) -> str:
        """
        Apply basic information scrambling techniques
        
        Args:
            text: The text to scramble
            agent_level: The agent's clearance level
            
        Returns:
            Scrambled text
        """
        # For Level 1-2, just lightly obfuscate specific details
        if agent_level <= 2:
            return self._obfuscate_specific_details(text)
        
        # For Level 3, mix in some misinformation
        elif agent_level == 3:
            return self._introduce_misinformation(text)
        
        # For Level 4-5, use more advanced techniques
        else:
            # Use deeper obfuscation for high-level agents
            text = self._replace_with_coded_language(text)
            text = self._introduce_misinformation(text)
            
            # Add a layer of abstraction
            text = self._add_abstraction_layer(text)
            
            return text
    
    def apply_layered_cipher_code(self, text: str, agent_level: int) -> str:
        """
        Apply the Layered Cipher Code (LCC) system from the SECRET INFO MANUAL
        
        This is a multi-layer cryptographic structure involving:
        1. Quantum Hashing - ensures no two messages use identical encryption patterns
        2. One-Time Pad (OTP) Key Exchange - simulated here with a secure hash
        3. Neural Signatures - simulated here with an agent-specific marker
        
        Args:
            text: The text to encrypt with LCC
            agent_level: The agent's clearance level
            
        Returns:
            LCC-encoded text
        """
        # For Level 4-5 only, others get basic scrambling
        if agent_level < 4:
            return self.apply_basic_scrambling(text, agent_level)
        
        # Start with full text
        processed_text = text
        
        # Layer 1: Quantum Hashing (simulated)
        # Add a timestamp-based hash to ensure uniqueness
        timestamp = datetime.utcnow().isoformat()
        quantum_hash = hashlib.sha256(f"{timestamp}:{text}".encode()).hexdigest()[:8]
        
        # Layer 2: Replace sensitive terms with coded references
        processed_text = self._replace_with_coded_language(processed_text)
        
        # Layer 3: Split the message into segments with coded markers
        segments = []
        
        # Split into sentences or chunks
        parts = re.split(r'(?<=[.!?])\s+', processed_text)
        for i, part in enumerate(parts):
            if not part.strip():
                continue
                
            # Add segment markers and rearrange some segments
            segment_id = f"[S{i+1:02d}]"
            segments.append(f"{segment_id} {part}")
        
        # Potentially reorder some segments for higher levels
        if agent_level == 5 and len(segments) > 2:
            # Swap one pair of segments to create intentional disorder
            swap_index = random.randint(0, len(segments) - 2)
            segments[swap_index], segments[swap_index + 1] = segments[swap_index + 1], segments[swap_index]
        
        # Join segments with Hash-Key verification points
        joined_text = "\n".join(segments)
        
        # Add a verification header and footer
        header = f"[LCC-V{agent_level}] [QH:{quantum_hash}] BEGIN TRANSMISSION"
        footer = f"END TRANSMISSION [KEY-VERIFY:{hashlib.md5(joined_text.encode()).hexdigest()[:6]}]"
        
        final_text = f"{header}\n\n{joined_text}\n\n{footer}"
        
        return final_text
    
    def _obfuscate_specific_details(self, text: str) -> str:
        """Obfuscate specific details while keeping the general meaning"""
        # Replace specific details like dates, times, locations
        
        # Replace dates with approximate ones
        text = re.sub(
            r'\b(\d{1,2})[/.-](\d{1,2})[/.-](\d{2,4})\b', 
            lambda m: f"approximately {'early' if int(m.group(2)) <= 4 else 'mid' if int(m.group(2)) <= 8 else 'late'} {m.group(3)}",
            text
        )
        
        # Replace exact times with time ranges
        text = re.sub(
            r'\b(\d{1,2}):(\d{2})\s*(am|pm|AM|PM)?\b',
            lambda m: f"between {int(m.group(1))-1 if int(m.group(1)) > 1 else 12}-{int(m.group(1))+1 if int(m.group(1)) < 12 else 1} {m.group(3) if m.group(3) else ''}",
            text
        )
        
        # Replace specific locations with more general ones
        for location in self.locations:
            if location in text:
                region = self._get_region_for_location(location)
                text = text.replace(location, f"a location in {region}")
        
        return text
    
    def _get_region_for_location(self, location: str) -> str:
        """Get the general region for a specific location"""
        regions = {
            "Europe": ["Berlin", "Vienna", "Prague", "Warsaw", "Budapest", "Kyiv", 
                       "Moscow", "Paris", "London", "Zurich", "Rome", "Madrid"],
            "Middle East": ["Istanbul", "Cairo", "Riyadh", "Tehran"],
            "Asia": ["Delhi", "Beijing", "Tokyo", "Seoul", "Bangkok", "Singapore"],
            "Oceania": ["Sydney", "Auckland"],
            "Africa": ["Johannesburg", "Lagos", "Nairobi"],
            "South America": ["Buenos Aires", "Bogota", "Lima"],
            "North America": ["Mexico City", "Washington", "New York", "Toronto"]
        }
        
        for region, cities in regions.items():
            if location in cities:
                return region
        
        return "an undisclosed region"
    
    def _introduce_misinformation(self, text: str) -> str:
        """Introduce some misinformation while keeping core meaning"""
        # Make a small change to dates if present
        text = re.sub(
            r'\b(\d{1,2})[/.-](\d{1,2})[/.-](\d{2,4})\b', 
            lambda m: f"{int(m.group(1))+random.randint(-2, 2)}/{int(m.group(2))+random.randint(-1, 1)}/{m.group(3)}",
            text
        )
        
        # Modify numbers slightly
        text = re.sub(
            r'\b(\d+)\b',
            lambda m: str(int(m.group(1)) + random.randint(-3, 3)) if int(m.group(1)) > 5 else m.group(1),
            text
        )
        
        # Insert occasional misleading info
        sentences = re.split(r'(?<=[.!?])\s+', text)
        if len(sentences) > 2:
            insert_index = random.randint(1, len(sentences) - 1)
            
            misleading_info = [
                f"Preliminary data suggested {random.choice(self.random_data)} could be a factor, but this was ruled out.",
                f"Initial reports connecting this to {random.choice(self.operation_names)} were incorrect.",
                f"Agent {random.choice(self.agent_names)} provided counter-intelligence that later proved to be misdirection.",
                f"Satellite imaging revealed anomalous {random.choice(self.random_data)}, but this was determined to be unrelated."
            ]
            
            sentences.insert(insert_index, random.choice(misleading_info))
            
            text = " ".join(sentences)
        
        return text
    
    def _replace_with_coded_language(self, text: str) -> str:
        """Replace specific terms with coded language"""
        # Replace operation names
        for operation in self.operation_names:
            if operation in text:
                code = "OP-" + hashlib.md5(operation.encode()).hexdigest()[:4].upper()
                text = text.replace(operation, code)
        
        # Replace agent names
        for agent in self.agent_names:
            if agent in text:
                code = "ASSET-" + hashlib.md5(agent.encode()).hexdigest()[:3].upper()
                text = text.replace(agent, code)
        
        # Replace locations with coded references
        for location in self.locations:
            if location in text:
                code = "SITE-" + hashlib.md5(location.encode()).hexdigest()[:3].upper()
                text = text.replace(location, code)
        
        # Replace dates with encoded versions
        text = re.sub(
            r'\b(\d{1,2})[/.-](\d{1,2})[/.-](\d{2,4})\b', 
            lambda m: f"T-MARK-{int(m.group(1))+int(m.group(2))+int(m.group(3))%100:02d}",
            text
        )
        
        return text
    
    def _add_abstraction_layer(self, text: str) -> str:
        """Add a layer of abstraction to the text"""
        # Add ambiguous framing
        prefix_options = [
            "Analysis suggests potential correlation with:",
            "Contingent interpretation based on available parameters:",
            "Encrypted channel indicated possible scenario:",
            "Cross-reference yields the following assessment:",
            "Pattern recognition algorithm response:"
        ]
        
        suffix_options = [
            "Verification pending.",
            "Confidence level: variable.",
            "Assessment subject to Shadow Protocol revisions.",
            "Multiple interpretations possible.",
            "Encrypted supplementary data available upon request."
        ]
        
        # Add prefix and suffix
        prefixed_text = random.choice(prefix_options) + "\n\n" + text
        
        if not text.endswith("."):
            prefixed_text += "."
        
        prefixed_text += "\n\n" + random.choice(suffix_options)
        
        return prefixed_text
    
    def decode_lcc(self, encrypted_text: str) -> str:
        """
        Decode a message encrypted with the LCC system
        
        Args:
            encrypted_text: The LCC-encrypted text
            
        Returns:
            Decoded text
        """
        # This function would implement the decoding process for LCC
        # In a real implementation, this would require the agent's neural signature
        # and proper key exchange
        
        # For this simulation, we just extract the message between the header and footer
        if not "[LCC-" in encrypted_text or not "BEGIN TRANSMISSION" in encrypted_text:
            logger.warning("Not a valid LCC-encrypted message")
            return encrypted_text
        
        try:
            # Extract the message content
            header_end = encrypted_text.find("BEGIN TRANSMISSION") + len("BEGIN TRANSMISSION")
            footer_start = encrypted_text.find("END TRANSMISSION")
            
            if footer_start < 0:
                return encrypted_text
            
            message = encrypted_text[header_end:footer_start].strip()
            
            # Remove segment markers
            message = re.sub(r'\[S\d+\]\s*', '', message)
            
            return message
        except Exception as e:
            logger.error(f"Error decoding LCC: {e}")
            return encrypted_text