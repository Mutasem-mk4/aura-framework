import sys
import json
import logging

logger = logging.getLogger("aura")

class Ingestor:
    """Handles data ingestion from various sources."""
    
    @staticmethod
    def read_stdin():
        """Reads data from standard input."""
        if sys.stdin.isatty():
            return None
        
        data = sys.stdin.read()
        return data

    @staticmethod
    def parse_json(data):
        """Attempts to parse data as JSON."""
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return None

    @staticmethod
    def process_input(input_data):
        """Generic input processor."""
        # Check if it's a list of lines or a single string
        lines = input_data.strip().split("\n")
        results = []
        for line in lines:
            json_data = Ingestor.parse_json(line)
            if json_data:
                results.append(json_data)
            else:
                # Fallback to plain text recording
                results.append({"raw": line})
        return results
