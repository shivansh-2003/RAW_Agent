#!/usr/bin/env python3
# agent_terminal.py

import os
import sys
import json
import time
import argparse
import getpass
import requests
import logging
import uuid
import hmac
import hashlib
import base64
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("agent_terminal.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("shadow_agent_terminal")

# Console for rich output
console = Console()

# Configuration
API_BASE_URL = os.getenv("SHADOW_API_URL", "https://api.shadow.rin")
CLIENT_VERSION = "1.0.0"
SIGNATURE_SECRET = os.getenv("SIGNATURE_SECRET", "")

class AgentTerminal:
    """
    Secure terminal interface for RAW agents to interact with Project SHADOW.
    This terminal allows agents with proper clearance to submit queries and
    receive secured responses according to the RAG CASE RESPONSE FRAMEWORK.
    """
    
    def __init__(self):
        """Initialize the Agent Terminal"""
        self.agent_id = None
        self.agent_level = None
        self.codename = None
        self.session_id = None
        self.access_token = None
        self.refresh_token = None
        
        # Load configuration
        self.config = self._load_config()
        
        # Security
        self.trusted_cert_path = self.config.get("trusted_cert_path")
        self.verify_ssl = self.config.get("verify_ssl", True)
        
        # Load cached session if available
        self._load_session()
        
        logger.info("Agent Terminal initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        config_file = os.path.expanduser("~/.shadow/config.json")
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading config: {e}")
        
        # Default config
        return {
            "api_url": API_BASE_URL,
            "verify_ssl": True,
            "session_cache": os.path.expanduser("~/.shadow/session.json"),
            "trusted_cert_path": None
        }
    
    def _save_session(self):
        """Save session information to file"""
        session_file = self.config.get("session_cache")
        
        if not session_file:
            return
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(session_file), exist_ok=True)
            
            with open(session_file, 'w') as f:
                json.dump({
                    "agent_id": self.agent_id,
                    "agent_level": self.agent_level,
                    "codename": self.codename,
                    "session_id": self.session_id,
                    "access_token": self.access_token,
                    "refresh_token": self.refresh_token,
                    "timestamp": datetime.utcnow().isoformat()
                }, f)
        except Exception as e:
            logger.error(f"Error saving session: {e}")
    
    def _load_session(self):
        """Load session information from file"""
        session_file = self.config.get("session_cache")
        
        if not session_file or not os.path.exists(session_file):
            return
        
        try:
            with open(session_file, 'r') as f:
                session_data = json.load(f)
                
                # Check if session is recent (last 24 hours)
                session_time = datetime.fromisoformat(session_data.get("timestamp", "2000-01-01T00:00:00"))
                if (datetime.utcnow() - session_time).total_seconds() > 86400:
                    # Session too old, don't load
                    return
                
                self.agent_id = session_data.get("agent_id")
                self.agent_level = session_data.get("agent_level")
                self.codename = session_data.get("codename")
                self.session_id = session_data.get("session_id")
                self.access_token = session_data.get("access_token")
                self.refresh_token = session_data.get("refresh_token")
                
                logger.info(f"Loaded session for agent {self.agent_id}")
        except Exception as e:
            logger.error(f"Error loading session: {e}")
    
    def _clear_session(self):
        """Clear session information"""
        self.agent_id = None
        self.agent_level = None
        self.codename = None
        self.session_id = None
        self.access_token = None
        self.refresh_token = None
        
        # Remove session file
        session_file = self.config.get("session_cache")
        if session_file and os.path.exists(session_file):
            try:
                os.remove(session_file)
            except Exception as e:
                logger.error(f"Error removing session file: {e}")
    
    def _get_neural_signature(self) -> Optional[str]:
        """
        Collect neural signature data for high-clearance authentication
        
        In a real implementation, this would interface with hardware
        that can collect neural/biometric data. For this simulation,
        we'll just create a random signature.
        """
        console.print("[yellow]Neural signature verification required for your clearance level...[/]")
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Reading neural signature...", total=100)
            for _ in range(10):
                progress.update(task, advance=10)
                time.sleep(0.2)
        
        # Generate a mock neural signature
        # In a real implementation, this would be actual biometric data
        mock_signature = base64.b64encode(os.urandom(128)).decode('utf-8')
        return mock_signature
    
    def _perform_handshake(self) -> bool:
        """
        Perform the secure handshake protocol as specified in the SECRET INFO MANUAL
        
        Returns:
            True if handshake is successful
        """
        console.print("[bold]Initiating Handshake Protocol[/bold]")
        
        # Step 1: Blink twice in a 2-second interval
        console.print("Step 1: Please blink twice in a 2-second interval...")
        time.sleep(2)
        
        # Step 2: Tap the left wrist once
        console.print("Step 2: Please tap your left wrist once...")
        time.sleep(1)
        
        # Step 3: Recite the appropriate phrase
        # In a real implementation, this would validate voice patterns
        phrase = self._get_current_phrase()
        console.print(f"Step 3: Please recite: '[bold]{phrase}[/bold]'")
        input("Press Enter after reciting the phrase...")
        
        console.print("[green]Handshake protocol completed successfully.[/green]")
        return True
    
    def _get_current_phrase(self) -> str:
        """Get the current operational phrase (rotates every 48 hours)"""
        # Get current timestamp in days, divide by 2 for 48-hour rotation
        day_of_year = datetime.utcnow().timetuple().tm_yday
        phrase_index = (day_of_year // 2) % len(self.operational_phrases)
        return self.operational_phrases[phrase_index]
    
    # Possible operational phrases
    operational_phrases = [
        "The eagle flies at midnight",
        "Distant thunder echoes twice",
        "Autumn leaves fall silently",
        "The mountain stands alone",
        "Silver moonlight reveals truth",
        "Whispers carry through shadows",
        "The river knows all secrets",
        "Golden dawn breaks the silence"
    ]
    
    def _generate_request_signature(self, data: str, timestamp: str, nonce: str) -> str:
        """Generate HMAC signature for request"""
        if not SIGNATURE_SECRET:
            return ""
        
        message = f"{timestamp}:{nonce}:{data}".encode('utf-8')
        signature = hmac.new(
            SIGNATURE_SECRET.encode('utf-8'),
            message,
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def _make_api_request(
        self, 
        endpoint: str, 
        method: str = "GET", 
        data: Dict[str, Any] = None,
        authenticate: bool = True
    ) -> Tuple[int, Dict[str, Any]]:
        """
        Make an authenticated API request
        
        Args:
            endpoint: API endpoint to call
            method: HTTP method (GET, POST, etc.)
            data: Request data for POST/PUT
            authenticate: Whether to include authentication token
            
        Returns:
            Tuple of (status_code, response_data)
        """
        url = f"{self.config.get('api_url', API_BASE_URL)}/{endpoint}"
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"SHADOW-Agent-Terminal/{CLIENT_VERSION}",
            "X-Client-Version": CLIENT_VERSION
        }
        
        # Add authentication if requested and available
        if authenticate and self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        
        # Add signature for secure transmission
        timestamp = str(int(time.time()))
        nonce = str(uuid.uuid4())
        
        data_str = json.dumps(data) if data else ""
        signature = self._generate_request_signature(data_str, timestamp, nonce)
        
        if signature:
            headers["X-Timestamp"] = timestamp
            headers["X-Nonce"] = nonce
            headers["X-Signature"] = signature
        
        try:
            # Determine SSL verification
            verify = self.trusted_cert_path if self.trusted_cert_path else self.verify_ssl
            
            if method.upper() == "GET":
                response = requests.get(url, headers=headers, verify=verify)
            elif method.upper() == "POST":
                response = requests.post(url, headers=headers, json=data, verify=verify)
            elif method.upper() == "PUT":
                response = requests.put(url, headers=headers, json=data, verify=verify)
            elif method.upper() == "DELETE":
                response = requests.delete(url, headers=headers, verify=verify)
            else:
                logger.error(f"Unsupported HTTP method: {method}")
                return 400, {"error": "Unsupported HTTP method"}
            
            # Try to parse JSON response
            try:
                response_data = response.json()
            except:
                response_data = {"error": "Invalid JSON response"}
            
            # Handle authentication errors
            if response.status_code == 401 and authenticate and self.refresh_token:
                # Try to refresh the token
                logger.info("Access token expired, attempting to refresh")
                refresh_success = self._refresh_authentication()
                
                if refresh_success:
                    # Retry the request with the new token
                    return self._make_api_request(endpoint, method, data, authenticate)
            
            return response.status_code, response_data
            
        except requests.RequestException as e:
            logger.error(f"API request error: {e}")
            return 500, {"error": f"Connection error: {str(e)}"}
    
    def login(self) -> bool:
        """
        Authenticate with the SHADOW API
        
        Returns:
            True if authentication successful
        """
        console.print(Panel(
            "[bold cyan]SHADOW Authentication System[/bold cyan]\n"
            "[yellow]Enter your credentials to access Project SHADOW[/yellow]"
        ))
        
        # Get credentials
        username = Prompt.ask("[bold]Username[/bold]")
        password = getpass.getpass("Password: ")
        
        # For Level 3+ agents, require TOTP code
        totp_code = None
        if username.lower().startswith(("l3-", "l4-", "l5-")):
            totp_code = Prompt.ask("[bold]TOTP Code[/bold] (for Level 3+)")
        
        # For Level 5 agents, collect neural signature
        neural_signature_data = None
        if username.lower().startswith("l5-"):
            neural_signature_data = self._get_neural_signature()
        
        # Perform the handshake protocol
        if not self._perform_handshake():
            console.print("[bold red]Handshake protocol failed. Authentication aborted.[/bold red]")
            return False
        
        # Prepare authentication data
        auth_data = {
            "username": username,
            "password": password
        }
        
        if totp_code:
            auth_data["totp_code"] = totp_code
        
        if neural_signature_data:
            auth_data["neural_signature_data"] = neural_signature_data
        
        # Make authentication request
        with console.status("[bold green]Authenticating...[/bold green]"):
            status_code, response = self._make_api_request(
                "auth/login",
                method="POST",
                data=auth_data,
                authenticate=False
            )
        
        if status_code == 200 and "access_token" in response:
            # Authentication successful
            self.access_token = response.get("access_token")
            self.refresh_token = response.get("refresh_token")
            self.agent_level = response.get("clearance_level")
            self.codename = response.get("codename")
            
            # Get agent ID from token payload
            import jwt
            try:
                token_parts = self.access_token.split(".")
                if len(token_parts) >= 2:
                    # Decode the payload (second part)
                    padded = token_parts[1] + "=" * ((4 - len(token_parts[1]) % 4) % 4)
                    payload = json.loads(base64.b64decode(padded).decode('utf-8'))
                    self.agent_id = payload.get("agent_id")
                    self.session_id = payload.get("session_id")
            except:
                # If token parsing fails, use a default agent ID
                self.agent_id = f"agent-{int(time.time())}"
            
            # Save the session
            self._save_session()
            
            # Display success message
            level_badges = {
                1: "[bold white on blue]LEVEL 1[/bold white on blue]",
                2: "[bold white on green]LEVEL 2[/bold white on green]",
                3: "[bold white on yellow]LEVEL 3[/bold white on yellow]",
                4: "[bold white on red]LEVEL 4[/bold white on red]",
                5: "[bold white on purple]LEVEL 5[/bold white on purple]"
            }
            
            level_badge = level_badges.get(self.agent_level, "[bold]UNKNOWN LEVEL[/bold]")
            
            console.print(Panel(
                f"[bold green]Authentication successful![/bold green]\n\n"
                f"Agent: [bold]{self.agent_id}[/bold]\n"
                f"Codename: [bold]{self.codename}[/bold]\n"
                f"Clearance: {level_badge}"
            ))
            
            return True
        else:
            # Authentication failed
            error_msg = response.get("detail", "Unknown authentication error")
            console.print(f"[bold red]Authentication failed:[/bold red] {error_msg}")
            return False
    
    def _refresh_authentication(self) -> bool:
        """
        Refresh the authentication token
        
        Returns:
            True if refresh successful
        """
        if not self.refresh_token:
            return False
        
        # Prepare refresh request
        refresh_data = {
            "refresh_token": self.refresh_token
        }
        
        # Make refresh request
        status_code, response = self._make_api_request(
            "auth/refresh",
            method="POST",
            data=refresh_data,
            authenticate=False
        )
        
        if status_code == 200 and "access_token" in response:
            # Refresh successful
            self.access_token = response.get("access_token")
            self.refresh_token = response.get("refresh_token")
            
            # Update session
            self._save_session()
            
            logger.info("Authentication refreshed successfully")
            return True
        else:
            # Refresh failed
            logger.error(f"Authentication refresh failed: {response}")
            return False
    
    def logout(self) -> bool:
        """
        Log out and invalidate the current session
        
        Returns:
            True if logout successful
        """
        if not self.access_token:
            console.print("[yellow]Not currently logged in.[/yellow]")
            return True
        
        # Revoke token
        with console.status("[bold green]Logging out...[/bold green]"):
            status_code, response = self._make_api_request(
                "auth/revoke-token",
                method="POST",
                data={"token": self.access_token, "token_type": "access"}
            )
        
        # Clear session regardless of server response
        self._clear_session()
        
        if status_code == 200:
            console.print("[green]Logged out successfully.[/green]")
            return True
        else:
            console.print("[yellow]Logout completed with warnings (server error).[/yellow]")
            return False
    
    def submit_query(self, query_text: str) -> bool:
        """
        Submit a query to the SHADOW API
        
        Args:
            query_text: The query to submit
            
        Returns:
            True if query was processed successfully
        """
        if not self.access_token:
            console.print("[bold red]Authentication required. Please login first.[/bold red]")
            return False
        
        # Prepare query data
        query_data = {
            "query_text": query_text,
            "agent_id": self.agent_id,
            "agent_level": self.agent_level,
            "session_id": self.session_id,
            "metadata": {
                "client_version": CLIENT_VERSION,
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        
        # For Level 5 agents on high-security queries, collect neural signature
        if self.agent_level == 5 and any(term in query_text.lower() for term in [
            "nuclear", "void", "eclipse", "deep-cover", "permanent", "hidden"
        ]):
            query_data["neural_signature_data"] = self._get_neural_signature()
        
        # Submit the query
        with console.status("[bold green]Processing query...[/bold green]"):
            status_code, response = self._make_api_request(
                "api/query", 
                method="POST",
                data=query_data
            )
        
        if status_code == 200:
            # Format the response based on agent level
            self._display_response(response)
            return True
        elif status_code == 403:
            console.print("[bold red]Access denied.[/bold red] Insufficient clearance level.")
            return False
        else:
            error_msg = response.get("detail", "Unknown error")
            console.print(f"[bold red]Error:[/bold red] {error_msg}")
            return False
    
    def _display_response(self, response: Dict[str, Any]):
        """Format and display response based on agent level"""
        greeting = response.get("greeting", "")
        response_text = response.get("response_text", "")
        
        # Different formatting based on agent level
        if self.agent_level >= 4:
            # High-level agents get minimal styling
            console.print(f"[grey]{greeting}[/grey]")
            console.print(response_text)
        elif self.agent_level == 3:
            # Level 3 gets analytical formatting
            console.print(Panel(
                f"[bold cyan]{greeting}[/bold cyan]\n\n{response_text}",
                title="SHADOW Response",
                border_style="cyan"
            ))
        elif self.agent_level == 2:
            # Level 2 gets tactical formatting
            console.print(f"[bold green]{greeting}[/bold green]")
            console.print(Panel(response_text, border_style="green"))
        else:
            # Level 1 gets the most help and formatting
            console.print(Panel(
                f"[bold blue]{greeting}[/bold blue]\n\n{response_text}",
                title="[bold]SHADOW Response[/bold]",
                border_style="blue",
                padding=(1, 2)
            ))
    
    def run_cli(self):
        """Run the interactive command-line interface"""
        console.print(Panel(
            "[bold cyan]PROJECT SHADOW - Agent Terminal[/bold cyan]\n"
            "[yellow]Research and Analysis Wing (RAW) Intelligence Retrieval System[/yellow]\n"
            "[red]CLASSIFIED LEVEL 7[/red]",
            border_style="red"
        ))
        
        console.print("Type [bold]help[/bold] for available commands.")
        
        while True:
            try:
                if self.agent_id:
                    # Display prompt based on clearance level
                    level_colors = {
                        1: "blue", 2: "green", 3: "yellow", 4: "red", 5: "purple"
                    }
                    color = level_colors.get(self.agent_level, "white")
                    prompt = f"[bold {color}]{self.codename}@SHADOW[/bold {color}]> "
                else:
                    prompt = "[bold]SHADOW[/bold]> "
                
                command = Prompt.ask(prompt)
                
                if command.lower() == "exit" or command.lower() == "quit":
                    # Log out first
                    if self.access_token:
                        self.logout()
                    break
                elif command.lower() == "help":
                    self._show_help()
                elif command.lower() == "login":
                    self.login()
                elif command.lower() == "logout":
                    self.logout()
                elif command.lower() == "status":
                    self._show_status()
                elif command.lower().startswith("query "):
                    query_text = command[6:].strip()
                    self.submit_query(query_text)
                elif command.lower() == "clear":
                    os.system('cls' if os.name == 'nt' else 'clear')
                else:
                    # If not a command, treat as a query
                    if command.strip():
                        self.submit_query(command)
            except KeyboardInterrupt:
                console.print("\n[yellow]Operation cancelled.[/yellow]")
            except Exception as e:
                console.print(f"[bold red]Error:[/bold red] {str(e)}")
        
        console.print("[bold]Exiting SHADOW Terminal. All connections terminated.[/bold]")
    
    def _show_help(self):
        """Display available commands"""
        help_table = Table(title="Available Commands")
        help_table.add_column("Command", style="cyan")
        help_table.add_column("Description", style="green")
        
        help_table.add_row("login", "Authenticate with the SHADOW system")
        help_table.add_row("logout", "Terminate current session")
        help_table.add_row("query <text>", "Submit a query to the system")
        help_table.add_row("status", "Show current session status")
        help_table.add_row("clear", "Clear the terminal screen")
        help_table.add_row("help", "Show this help message")
        help_table.add_row("exit", "Exit the terminal")
        
        console.print(help_table)
    
    def _show_status(self):
        """Display current session status"""
        if not self.agent_id:
            console.print("[yellow]Not currently logged in.[/yellow]")
            return
        
        level_badges = {
            1: "[bold white on blue]LEVEL 1[/bold white on blue]",
            2: "[bold white on green]LEVEL 2[/bold white on green]",
            3: "[bold white on yellow]LEVEL 3[/bold white on yellow]",
            4: "[bold white on red]LEVEL 4[/bold white on red]",
            5: "[bold white on purple]LEVEL 5[/bold white on purple]"
        }
        
        level_badge = level_badges.get(self.agent_level, "[bold]UNKNOWN LEVEL[/bold]")
        
        # Try to get session info
        valid_session = False
        with console.status("[bold green]Checking session status...[/bold green]"):
            status_code, response = self._make_api_request("api/session/verify")
            valid_session = status_code == 200
        
        status_text = "[bold green]Active[/bold green]" if valid_session else "[bold red]Expired[/bold red]"
        
        console.print(Panel(
            f"[bold]Agent ID:[/bold] {self.agent_id}\n"
            f"[bold]Codename:[/bold] {self.codename}\n"
            f"[bold]Clearance:[/bold] {level_badge}\n"
            f"[bold]Session ID:[/bold] {self.session_id}\n"
            f"[bold]Session Status:[/bold] {status_text}\n",
            title="SHADOW Session Status"
        ))

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="SHADOW Agent Terminal")
    parser.add_argument("-q", "--query", help="Submit a query and exit")
    parser.add_argument("--non-interactive", action="store_true", help="Non-interactive mode")
    
    args = parser.parse_args()
    
    terminal = AgentTerminal()
    
    if args.non_interactive:
        # Non-interactive mode
        if not terminal.agent_id:
            # Can't do anything without authentication
            print("Authentication required. Run in interactive mode first.")
            return 1
        
        if args.query:
            success = terminal.submit_query(args.query)
            return 0 if success else 1
        
        return 0
    else:
        # Interactive mode
        terminal.run_cli()
        return 0

if __name__ == "__main__":
    sys.exit(main())