# In log_collector.py
import json
import logging
import asyncio
import os
import aiofiles
from typing import Dict, Any, AsyncGenerator
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class LogCollector:
    def __init__(self, log_sources: list, storage_backend):
        self.log_sources = log_sources
        self.storage = storage_backend

    async def collect_from_file(self, file_path: str) -> AsyncGenerator[Dict[str, Any], None]:
        """Collect logs from a file (async tail -f like behavior)"""
        logging.info(f"Starting to tail file: {file_path}")
        
        # Wait for file to exist
        while not os.path.exists(file_path):
            logging.warning(f"File {file_path} not found. Waiting...")
            await asyncio.sleep(5)

        try:
            async with aiofiles.open(file_path, 'r') as f:
                await f.seek(0, 2)  # Go to end of file
                while True:
                    line = await f.readline()
                    if line:
                        yield self.parse_log_line(line.strip(), file_path)
                    else:
                        await asyncio.sleep(0.1)  # Use non-blocking sleep
        except Exception as e:
            logging.error(f"Error reading {file_path}: {e}")

    def parse_log_line(self, line: str, source: str) -> Dict[str, Any]:
        """Parse log line into structured format"""
        try:
            if line.startswith('{'):
                log_data = json.loads(line)
            else:
                log_data = self.parse_common_format(line)

            # Ensure timestamp exists
            timestamp = log_data.get('timestamp', datetime.utcnow().isoformat())

            log_data.update({
                'timestamp': timestamp,
                'source': source,
                'raw_log': line
            })
            return log_data

        except Exception as e:
            logging.warning(f"Failed to parse log line: {line[:100]}... Error: {e}")
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'source': source,
                'raw_log': line,
                'error': 'ParseError'
            }

    def parse_common_format(self, line: str) -> Dict[str, Any]:
        """Parse common log formats"""
        parts = line.split()
        if len(parts) >= 4:
            # Simple heuristic for common log format
            if self.is_ip(parts[0]):
                 return {
                    'ip': parts[0],
                    'message': ' '.join(parts[1:])
                }
        return {'message': line}

    @staticmethod
    def is_ip(s: str) -> bool:
        """Simple IP validation"""
        try:
            parts = s.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False