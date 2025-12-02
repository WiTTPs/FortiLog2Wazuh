import re
import json
import subprocess
import sys
from pathlib import Path

# ---------- Parameters ----------
# Usage: python fortilogparse.py input.pdf output.json
if len(sys.argv) != 3:
    print("Usage: python fortilogparse.py input.pdf output.json")
    sys.exit(1)

pdf_file = sys.argv[1]
json_file = sys.argv[2]

# Check if PDF exists
if not Path(pdf_file).is_file():
    print(f"PDF file '{pdf_file}' not found!")
    sys.exit(1)

# ---------- Convert PDF to text ----------
txt_file = "temp_out.txt"
subprocess.run(["pdftotext", "-layout", pdf_file, txt_file], check=True)

# ---------- Regex patterns for each field ----------
fields = ['Message ID', 'Message Description', 'Message Meaning', 'Type', 'Category', 'Severity']

patterns = {
    'Message ID': r'^Message ID:\s*(.+)$',
    'Message Description': r'^Message Description:\s+(.+)$',
    'Message Meaning': r'^Message Meaning:\s+(.+)$',
    'Type': r'^Type:\s+(.+)$',
    'Category': r'^Category:\s+(.+)$',
    'Severity': r'^Severity:\s+(.+)$'
}

# ---------- Process text file ----------
entries = []
current_entry = {field: None for field in fields}
distinct_ids = set()  # to track unique Message IDs

with open(txt_file, 'r', encoding='utf-8') as file:
    for line in file:
        line = line.strip()
        for key, pattern in patterns.items():
            match = re.match(pattern, line)
            if match:
                # If a new Message ID is found, save the previous entry
                if key == 'Message ID' and current_entry['Message ID'] is not None:
                    entries.append(current_entry)
                    distinct_ids.add(current_entry['Message ID'])
                    current_entry = {field: None for field in fields}
                current_entry[key] = match.group(1)
                break

# ---------- Add last entry ----------
if current_entry['Message ID'] is not None:
    entries.append(current_entry)
    distinct_ids.add(current_entry['Message ID'])

# ---------- Export to JSON ----------
output_data = {
    "distinct_message_ids": len(distinct_ids),
    "entries": entries
}

with open(json_file, 'w', encoding='utf-8') as out_file:
    json.dump(output_data, out_file, indent=4)

print(f"Data successfully extracted from '{pdf_file}' and saved as '{json_file}'!")
print(f"Total distinct Message IDs: {len(distinct_ids)}")
