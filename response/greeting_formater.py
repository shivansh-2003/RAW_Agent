# greeting_formatter.py

import logging
import random
from typing import Dict, List, Optional
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("greeting_formatter.log")
    ]
)
logger = logging.getLogger("shadow_greeting_formatter")

class GreetingFormatter:
    """
    Agent-Level Greeting Formatter for Project SHADOW
    
    This component generates appropriate greetings for agents based on their
    clearance level, as specified in the RAG CASE RESPONSE FRAMEWORK.
    """
    
    def __init__(self):
        """Initialize the Greeting Formatter with level-specific greetings"""
        # Basic greetings from the framework
        self.standard_greetings = {
            1: "Salute, Shadow Cadet.",
            2: "Bonjour, Sentinel.",
            3: "Eyes open, Phantom.",
            4: "In the wind, Commander.",
            5: "The unseen hand moves, Whisper."
        }
        
        # Alternative greetings for variation (maintaining the same style)
        self.alternative_greetings = {
            1: [
                "Welcome, Shadow Cadet.",
                "Greetings, Shadow Cadet.",
                "Shadow Cadet, online and secured.",
                "Ready to assist, Shadow Cadet."
            ],
            2: [
                "Greetings, Sentinel.",
                "Sentinel, standing by.",
                "At your service, Sentinel.",
                "Sentinel, connection secure."
            ],
            3: [
                "Phantom, monitoring engaged.",
                "Watching the shadows, Phantom.",
                "Alert and ready, Phantom.",
                "Phantom, secure channel established."
            ],
            4: [
                "Commander, channel encrypted.",
                "Awaiting directive, Commander.",
                "Shadows hide us, Commander.",
                "Secure line established, Commander."
            ],
            5: [
                "Whisper, the network listens.",
                "The game continues, Whisper.",
                "Between silence and sound, Whisper.",
                "The void awaits your word, Whisper."
            ]
        }
        
        # Time-based greeting variations
        # Only for Level 3 and above who should be more situationally aware
        self.time_greetings = {
            3: {
                "morning": "Dawn breaks, Phantom.",
                "day": "Daylight exposes, Phantom.",
                "evening": "Shadows lengthen, Phantom.",
                "night": "Night conceals, Phantom."
            },
            4: {
                "morning": "First light brings clarity, Commander.",
                "day": "The sun reveals all paths, Commander.",
                "evening": "Twilight masks our movements, Commander.",
                "night": "Darkness is our ally, Commander."
            },
            5: {
                "morning": "The early hour speaks truths, Whisper.",
                "day": "Even in daylight, secrets remain, Whisper.",
                "evening": "The day fades, but our work continues, Whisper.",
                "night": "Night's veil covers many sins, Whisper."
            }
        }
        
        logger.info("Greeting Formatter initialized")
    
    def format_greeting(self, agent_level: int, use_time_greeting: bool = False) -> str:
        """
        Generate an appropriate greeting for the agent's clearance level
        
        Args:
            agent_level: The agent's clearance level (1-5)
            use_time_greeting: Whether to use time-based greetings (default: False)
            
        Returns:
            Formatted greeting
        """
        # Ensure valid agent level
        if agent_level not in range(1, 6):
            logger.warning(f"Invalid agent level: {agent_level}, defaulting to Level 1")
            agent_level = 1
        
        # Determine if we should use time-based greeting
        if use_time_greeting and agent_level >= 3:
            hour = datetime.utcnow().hour
            
            # Determine time of day
            if 5 <= hour < 12:
                time_of_day = "morning"
            elif 12 <= hour < 17:
                time_of_day = "day"
            elif 17 <= hour < 22:
                time_of_day = "evening"
            else:
                time_of_day = "night"
            
            # Use time-based greeting if available
            if time_of_day in self.time_greetings.get(agent_level, {}):
                return self.time_greetings[agent_level][time_of_day]
        
        # Usually use standard greeting (80% of the time)
        if random.random() < 0.8:
            greeting = self.standard_greetings[agent_level]
        else:
            # Otherwise use a random alternative greeting
            alternatives = self.alternative_greetings.get(agent_level, [])
            if alternatives:
                greeting = random.choice(alternatives)
            else:
                greeting = self.standard_greetings[agent_level]
        
        return greeting
    
    def get_all_greetings(self, agent_level: int) -> Dict[str, List[str]]:
        """
        Get all possible greetings for an agent level
        
        Args:
            agent_level: The agent's clearance level (1-5)
            
        Returns:
            Dictionary with standard, alternative, and time-based greetings
        """
        result = {
            "standard": self.standard_greetings.get(agent_level, "Greetings, Agent."),
            "alternative": self.alternative_greetings.get(agent_level, []),
            "time_based": self.time_greetings.get(agent_level, {})
        }
        
        return result