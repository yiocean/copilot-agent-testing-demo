#!/usr/bin/env python3
"""
Demo script showing the refactored data processor in action.
"""

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from data_processor import DataProcessor

def main():
    """Demonstrate the refactored data processor."""

    sample_data = [
        {
            "id": "1",
            "name": "john doe",
            "email": "john@example.com",
            "phone": "(555) 123-4567"
        },
        '{"id": "2", "name": "jane smith", "email": "jane@example.com", "phone": "555-987-6543"}',
        '<user><id>3</id><name>bob wilson</name><email>bob@example.com</email><phone>555-555-5555</phone></user>'
    ]

    with DataProcessor() as processor:
        print("Processing sample data...")

        result = processor.process_everything(
            input_data=sample_data,
            output_file="output.json",
            backup=True
        )

        print(f"Processing result: {json.dumps(result, indent=2)}")

        if processor.authenticate_user("admin", "testadmin"):
            print("Admin authentication successful")
        else:
            print("Admin authentication failed")

if __name__ == "__main__":
    main()