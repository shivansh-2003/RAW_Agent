import os
import json
import logging
import datetime
import hashlib
import hmac
import base64
import uuid
import gzip
import shutil
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class LogRecord:
    """A secure log record with cryptographic signature"""
    
    def __init__(
        self,
        level: str,
        message: str,
        timestamp: datetime.datetime,
        node_id: str,
        record_id: str,
        source: str,
        extra: Optional[Dict[str, Any]] = None,
        previous_signature: Optional[str] = None
    ):
        self.level = level
        self.message = message
        self.timestamp = timestamp
        self.node_id = node_id
        self.record_id = record_id
        self.source = source
        self.extra = extra or {}
        self.previous_signature = previous_signature
        self.signature = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert log record to dictionary for serialization"""
        return {
            "level": self.level,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "node_id": self.node_id,
            "record_id": self.record_id,
            "source": self.source,
            "extra": self.extra,
            "previous_signature": self.previous_signature,
            "signature": self.signature
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LogRecord':
        """Create a log record from dictionary data"""
        record = cls(
            level=data["level"],
            message=data["message"],
            timestamp=datetime.datetime.fromisoformat(data["timestamp"]),
            node_id=data["node_id"],
            record_id=data["record_id"],
            source=data["source"],
            extra=data.get("extra", {}),
            previous_signature=data.get("previous_signature")
        )
        record.signature = data.get("signature")
        return record
    
    def get_content_for_signature(self) -> str:
        """Get the content to be signed"""
        content = {
            "level": self.level,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "node_id": self.node_id,
            "record_id": self.record_id,
            "source": self.source,
            "extra": self.extra,
            "previous_signature": self.previous_signature
        }
        return json.dumps(content, sort_keys=True)
    
    def sign(self, key: bytes) -> None:
        """Sign the log record with the provided key"""
        content = self.get_content_for_signature()
        signature = hmac.new(key, content.encode('utf-8'), hashlib.sha256).hexdigest()
        self.signature = signature
    
    def verify_signature(self, key: bytes) -> bool:
        """Verify the log record's signature with the provided key"""
        if not self.signature:
            return False
        
        content = self.get_content_for_signature()
        expected_signature = hmac.new(key, content.encode('utf-8'), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_signature, self.signature)


class SecureLogger:
    """
    Secure logger with tamper-proof logging capabilities
    
    Features:
    - Tamper-proof logging with cryptographic signatures
    - Optional encryption of log content
    - Structured logging with metadata
    - Log rotation and archiving
    - Verification of log integrity
    """
    
    LOG_LEVELS = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }
    
    def __init__(
        self,
        name: str,
        log_level: str = "INFO",
        log_dir: str = "logs",
        node_id: Optional[str] = None,
        max_log_size_mb: int = 10,
        retention_days: int = 90,
        encryption_enabled: bool = False,
        key_file: Optional[str] = None
    ):
        """
        Initialize the secure logger
        
        Args:
            name: Logger name (used as source in log records)
            log_level: Minimum log level to record
            log_dir: Directory to store log files
            node_id: Unique identifier for this node (generated if not provided)
            max_log_size_mb: Maximum size of log file before rotation
            retention_days: Number of days to retain archived logs
            encryption_enabled: Whether to encrypt log content
            key_file: Path to file containing encryption and signing keys
        """
        self.name = name
        self.log_level = self._validate_log_level(log_level)
        self.log_dir = Path(log_dir)
        self.node_id = node_id or f"node-{uuid.uuid4().hex[:8]}"
        self.max_log_size_bytes = max_log_size_mb * 1024 * 1024
        self.retention_days = retention_days
        self.encryption_enabled = encryption_enabled
        
        # Create log directory if it doesn't exist
        self.log_dir.mkdir(parents=True, exist_ok=True)
        (self.log_dir / "archive").mkdir(exist_ok=True)
        
        # Initialize keys
        self._initialize_keys(key_file)
        
        # Set up standard Python logger for compatibility
        self._setup_standard_logger()
        
        # Initialize current log file
        self.current_log_file = self._get_current_log_file()
        
        # Read the last signature from the current log file
        self.last_signature = self._get_last_signature()
        
        # Perform log rotation check
        self._check_rotation()
        
        # Log initialization
        self.info(f"SecureLogger initialized", extra={
            "log_level": log_level,
            "encryption_enabled": encryption_enabled
        })
    
    def _validate_log_level(self, log_level: str) -> int:
        """Validate and convert log level string to int"""
        if log_level not in self.LOG_LEVELS:
            raise ValueError(f"Invalid log level: {log_level}. Must be one of {list(self.LOG_LEVELS.keys())}")
        return self.LOG_LEVELS[log_level]
    
    def _initialize_keys(self, key_file: Optional[str]) -> None:
        """Initialize encryption and signing keys"""
        if key_file and os.path.exists(key_file):
            # Load keys from file
            with open(key_file, 'rb') as f:
                key_data = json.loads(f.read())
                self.signing_key = base64.b64decode(key_data["signing_key"])
                if self.encryption_enabled:
                    self.encryption_key = base64.b64decode(key_data["encryption_key"])
        else:
            # Generate new keys
            self.signing_key = os.urandom(32)  # 256-bit key for HMAC
            
            if self.encryption_enabled:
                # Generate encryption key
                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend()
                )
                self.encryption_key = base64.urlsafe_b64encode(kdf.derive(os.urandom(32)))
                self.fernet = Fernet(self.encryption_key)
            
            # Save keys to file if key_file is specified
            if key_file:
                key_data = {
                    "signing_key": base64.b64encode(self.signing_key).decode('utf-8')
                }
                if self.encryption_enabled:
                    key_data["encryption_key"] = self.encryption_key.decode('utf-8')
                
                with open(key_file, 'wb') as f:
                    f.write(json.dumps(key_data).encode('utf-8'))
    
    def _setup_standard_logger(self) -> None:
        """Set up standard Python logger for compatibility"""
        self.std_logger = logging.getLogger(self.name)
        self.std_logger.setLevel(self.log_level)
        
        # Remove any existing handlers
        for handler in self.std_logger.handlers[:]:
            self.std_logger.removeHandler(handler)
        
        # Add console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(self.log_level)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        self.std_logger.addHandler(console_handler)
    
    def _get_current_log_file(self) -> Path:
        """Get the current log file path"""
        date_str = datetime.datetime.now().strftime("%Y%m%d")
        return self.log_dir / f"{self.name}_{date_str}.log"
    
    def _get_last_signature(self) -> Optional[str]:
        """Read the last signature from the current log file"""
        if not self.current_log_file.exists():
            return None
        
        try:
            with open(self.current_log_file, 'r') as f:
                lines = f.readlines()
                if not lines:
                    return None
                
                # Try to parse the last non-empty line as JSON
                for line in reversed(lines):
                    if line.strip():
                        try:
                            record_data = json.loads(line)
                            if "signature" in record_data:
                                return record_data["signature"]
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            self.std_logger.error(f"Error reading last signature: {e}")
        
        return None
    
    def _check_rotation(self) -> None:
        """Check if log rotation is needed and perform if necessary"""
        # Check if current log file exceeds max size
        if self.current_log_file.exists() and self.current_log_file.stat().st_size >= self.max_log_size_bytes:
            self._rotate_logs()
        
        # Check for old archives to remove
        self._cleanup_old_archives()
    
    def _rotate_logs(self) -> None:
        """Rotate log files"""
        if not self.current_log_file.exists():
            return
        
        # Create archive filename with timestamp
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_file = self.log_dir / "archive" / f"{self.name}_{timestamp}.log.gz"
        
        try:
            # Compress the log file
            with open(self.current_log_file, 'rb') as f_in:
                with gzip.open(archive_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Create a metadata file with verification info
            metadata = {
                "original_file": str(self.current_log_file.name),
                "archive_date": datetime.datetime.now().isoformat(),
                "node_id": self.node_id,
                "record_count": self._count_records(self.current_log_file),
                "final_signature": self.last_signature,
                "archive_hash": self._hash_file(archive_file)
            }
            
            # Sign the metadata
            metadata_content = json.dumps(metadata, sort_keys=True)
            metadata["metadata_signature"] = hmac.new(
                self.signing_key, 
                metadata_content.encode('utf-8'), 
                hashlib.sha256
            ).hexdigest()
            
            # Write metadata file
            with open(str(archive_file) + ".meta", 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Clear the current log file but maintain the chain of signatures
            self._create_empty_log_with_header()
            
            # Log rotation event
            self.info(f"Log rotated to archive", extra={
                "archive_file": str(archive_file.name),
                "record_count": metadata["record_count"]
            })
            
        except Exception as e:
            self.std_logger.error(f"Error during log rotation: {e}")
    
    def _count_records(self, log_file: Path) -> int:
        """Count the number of valid records in a log file"""
        count = 0
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            json.loads(line)
                            count += 1
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            self.std_logger.error(f"Error counting records: {e}")
        
        return count
    
    def _hash_file(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of a file"""
        hash_obj = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    
    def _create_empty_log_with_header(self) -> None:
        """Create an empty log file with a header that maintains the signature chain"""
        header_record = LogRecord(
            level="INFO",
            message="Log file created",
            timestamp=datetime.datetime.now(),
            node_id=self.node_id,
            record_id=str(uuid.uuid4()),
            source=self.name,
            extra={"rotation": True},
            previous_signature=self.last_signature
        )
        header_record.sign(self.signing_key)
        
        with open(self.current_log_file, 'w') as f:
            f.write(json.dumps(header_record.to_dict()) + '\n')
        
        self.last_signature = header_record.signature
    
    def _cleanup_old_archives(self) -> None:
        """Remove archives older than retention period"""
        if self.retention_days <= 0:
            return
        
        archive_dir = self.log_dir / "archive"
        if not archive_dir.exists():
            return
        
        cutoff_date = datetime.datetime.now() - datetime.timedelta(days=self.retention_days)
        
        for file in archive_dir.glob(f"{self.name}_*.log.gz"):
            try:
                # Extract date from filename (format: name_YYYYMMDD_HHMMSS.log.gz)
                date_str = file.name.replace(f"{self.name}_", "").split(".")[0]
                if "_" in date_str:
                    date_str = date_str.split("_")[0]
                
                file_date = datetime.datetime.strptime(date_str, "%Y%m%d")
                
                if file_date < cutoff_date:
                    # Also remove the metadata file if it exists
                    meta_file = Path(str(file) + ".meta")
                    if meta_file.exists():
                        meta_file.unlink()
                    
                    # Remove the archive file
                    file.unlink()
                    
                    self.info(f"Removed old archive file", extra={
                        "file": str(file.name),
                        "age_days": (datetime.datetime.now() - file_date).days
                    })
            except Exception as e:
                self.std_logger.error(f"Error cleaning up archive {file}: {e}")
    
    def _log(self, level: str, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Internal method to log a message with the specified level"""
        # Skip if level is below threshold
        if self.LOG_LEVELS[level] < self.log_level:
            return
        
        # Create log record
        record = LogRecord(
            level=level,
            message=message,
            timestamp=datetime.datetime.now(),
            node_id=self.node_id,
            record_id=str(uuid.uuid4()),
            source=self.name,
            extra=extra,
            previous_signature=self.last_signature
        )
        
        # Sign the record
        record.sign(self.signing_key)
        self.last_signature = record.signature
        
        # Get the JSON representation
        record_json = json.dumps(record.to_dict())
        
        # Encrypt if enabled
        if self.encryption_enabled:
            record_json = base64.b64encode(self.fernet.encrypt(record_json.encode('utf-8'))).decode('utf-8')
        
        # Write to log file
        try:
            with open(self.current_log_file, 'a') as f:
                f.write(record_json + '\n')
        except Exception as e:
            self.std_logger.error(f"Error writing to log file: {e}")
        
        # Also log to standard logger
        getattr(self.std_logger, level.lower())(message, extra=extra or {})
        
        # Check if rotation is needed after writing
        if self.current_log_file.stat().st_size >= self.max_log_size_bytes:
            self._rotate_logs()
    
    def debug(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log a debug message"""
        self._log("DEBUG", message, extra)
    
    def info(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log an info message"""
        self._log("INFO", message, extra)
    
    def warning(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log a warning message"""
        self._log("WARNING", message, extra)
    
    def error(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log an error message"""
        self._log("ERROR", message, extra)
    
    def critical(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log a critical message"""
        self._log("CRITICAL", message, extra)
    
    def verify_log_integrity(self, log_file: Optional[Path] = None) -> Dict[str, Any]:
        """
        Verify the integrity of a log file
        
        Args:
            log_file: Path to log file to verify (defaults to current log file)
            
        Returns:
            Dictionary with verification results
        """
        log_file = log_file or self.current_log_file
        
        if not log_file.exists():
            return {
                "verified": False,
                "error": "Log file does not exist",
                "file": str(log_file)
            }
        
        results = {
            "verified": True,
            "file": str(log_file),
            "records_checked": 0,
            "records_valid": 0,
            "records_invalid": 0,
            "chain_intact": True
        }
        
        prev_signature = None
        
        try:
            with open(log_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    if not line.strip():
                        continue
                    
                    results["records_checked"] += 1
                    
                    try:
                        # Decrypt if necessary
                        if self.encryption_enabled:
                            line = self.fernet.decrypt(base64.b64decode(line)).decode('utf-8')
                        
                        # Parse record
                        record_data = json.loads(line)
                        record = LogRecord.from_dict(record_data)
                        
                        # Verify signature
                        if record.verify_signature(self.signing_key):
                            results["records_valid"] += 1
                            
                            # Verify chain
                            if prev_signature is not None and record.previous_signature != prev_signature:
                                results["chain_intact"] = False
                                results["chain_break_at"] = line_num
                            
                            prev_signature = record.signature
                        else:
                            results["records_invalid"] += 1
                            results["first_invalid"] = results.get("first_invalid", line_num)
                    except Exception as e:
                        results["records_invalid"] += 1
                        results["first_invalid"] = results.get("first_invalid", line_num)
                        results["error_detail"] = str(e)
        except Exception as e:
            results["verified"] = False
            results["error"] = f"Error verifying log: {e}"
        
        results["verified"] = (
            results["records_invalid"] == 0 and 
            results["chain_intact"] and 
            results["records_checked"] > 0
        )
        
        return results
    
    def export_logs(
        self, 
        start_time: datetime.datetime, 
        end_time: datetime.datetime, 
        output_file: str,
        filter_level: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Export logs within a time range to a file
        
        Args:
            start_time: Start of time range
            end_time: End of time range
            output_file: Path to output file
            filter_level: Optional minimum log level to include
            
        Returns:
            Dictionary with export results
        """
        results = {
            "exported_records": 0,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "output_file": output_file
        }
        
        min_level = self.LOG_LEVELS.get(filter_level, 0) if filter_level else 0
        
        # Get all log files including archives
        log_files = [self.current_log_file]
        archive_files = list(sorted(
            (self.log_dir / "archive").glob(f"{self.name}_*.log.gz"),
            key=lambda p: p.name
        ))
        
        records = []
        
        # Process current log file
        try:
            with open(self.current_log_file, 'r') as f:
                for line in f:
                    if not line.strip():
                        continue
                    
                    try:
                        # Decrypt if necessary
                        if self.encryption_enabled:
                            line = self.fernet.decrypt(base64.b64decode(line)).decode('utf-8')
                        
                        # Parse record
                        record_data = json.loads(line)
                        record = LogRecord.from_dict(record_data)
                        
                        record_time = record.timestamp
                        
                        # Filter by time range
                        if start_time <= record_time <= end_time:
                            # Filter by level if specified
                            if not filter_level or self.LOG_LEVELS[record.level] >= min_level:
                                records.append(record.to_dict())
                    except Exception as e:
                        self.std_logger.error(f"Error processing log record: {e}")
        except Exception as e:
            self.std_logger.error(f"Error reading log file: {e}")
        
        # Process archive files if needed
        for archive_file in archive_files:
            try:
                # Extract date from filename
                date_str = archive_file.name.replace(f"{self.name}_", "").split(".")[0]
                if "_" in date_str:
                    date_str = date_str.split("_")[0]
                
                file_date = datetime.datetime.strptime(date_str, "%Y%m%d")
                
                # Skip if file date is outside range
                file_end_date = file_date + datetime.timedelta(days=1)
                if file_end_date < start_time or file_date > end_time:
                    continue
                
                # Read and process archive
                with gzip.open(archive_file, 'rt') as f:
                    for line in f:
                        if not line.strip():
                            continue
                        
                        try:
                            # Decrypt if necessary
                            if self.encryption_enabled:
                                line = self.fernet.decrypt(base64.b64decode(line)).decode('utf-8')
                            
                            # Parse record
                            record_data = json.loads(line)
                            record = LogRecord.from_dict(record_data)
                            
                            record_time = record.timestamp
                            
                            # Filter by time range
                            if start_time <= record_time <= end_time:
                                # Filter by level if specified
                                if not filter_level or self.LOG_LEVELS[record.level] >= min_level:
                                    records.append(record.to_dict())
                        except Exception as e:
                            self.std_logger.error(f"Error processing archive record: {e}")
            except Exception as e:
                self.std_logger.error(f"Error processing archive {archive_file}: {e}")
        
        # Sort records by timestamp
        records.sort(key=lambda r: r["timestamp"])
        
        # Write to output file
        try:
            with open(output_file, 'w') as f:
                for record in records:
                    f.write(json.dumps(record) + '\n')
            
            results["exported_records"] = len(records)
            results["success"] = True
        except Exception as e:
            results["success"] = False
            results["error"] = str(e)
        
        return results
    
    def search_logs(
        self,
        query: str,
        start_time: Optional[datetime.datetime] = None,
        end_time: Optional[datetime.datetime] = None,
        filter_level: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Search logs for matching records
        
        Args:
            query: Search query string
            start_time: Optional start of time range
            end_time: Optional end of time range
            filter_level: Optional minimum log level to include
            limit: Maximum number of records to return
            
        Returns:
            List of matching log records
        """
        start_time = start_time or (datetime.datetime.now() - datetime.timedelta(days=7))
        end_time = end_time or datetime.datetime.now()
        min_level = self.LOG_LEVELS.get(filter_level, 0) if filter_level else 0
        
        # Get all log files including archives
        log_files = [self.current_log_file]
        archive_files = list(sorted(
            (self.log_dir / "archive").glob(f"{self.name}_*.log.gz"),
            key=lambda p: p.name
        ))
        
        # Process newer files first (current log file, then archives in reverse chronological order)
        archive_files.reverse()
        all_files = [self.current_log_file] + archive_files
        
        matches = []
        
        for log_file in all_files:
            if len(matches) >= limit:
                break
            
            try:
                # Open file (handle both regular and gzip)
                if str(log_file).endswith('.gz'):
                    f = gzip.open(log_file, 'rt')
                else:
                    f = open(log_file, 'r')
                
                with f:
                    for line in f:
                        if not line.strip():
                            continue
                        
                        try:
                            # Decrypt if necessary
                            if self.encryption_enabled:
                                line = self.fernet.decrypt(base64.b64decode(line)).decode('utf-8')
                            
                            # Parse record
                            record_data = json.loads(line)
                            record = LogRecord.from_dict(record_data)
                            
                            record_time = record.timestamp
                            
                            # Filter by time range
                            if start_time <= record_time <= end_time:
                                # Filter by level if specified
                                if not filter_level or self.LOG_LEVELS[record.level] >= min_level:
                                    # Check for query match in message or extra data
                                    message_match = query.lower() in record.message.lower()
                                    extra_match = False
                                    
                                    if record.extra:
                                        extra_str = json.dumps(record.extra).lower()
                                        extra_match = query.lower() in extra_str
                                    
                                    if message_match or extra_match:
                                        matches.append(record.to_dict())
                                        
                                        if len(matches) >= limit:
                                            break
                        except Exception as e:
                            self.std_logger.error(f"Error processing log record during search: {e}")
            except Exception as e:
                self.std_logger.error(f"Error searching log file {log_file}: {e}")
        
        # Sort matches by timestamp (newest first)
        matches.sort(key=lambda r: r["timestamp"], reverse=True)
        
        return matches[:limit] 