import json
import sys
from pathlib import Path
import re

# ---------- Parameters ----------
# Usage: python generate_wazuh_rules.py input.json output.xml
if len(sys.argv) != 3:
    print("Usage: python generate_wazuh_rules.py input.json output.xml")
    sys.exit(1)

json_file = sys.argv[1]
wazuh_rules_file = sys.argv[2]

if not Path(json_file).is_file():
    print(f"JSON file '{json_file}' not found!")
    sys.exit(1)

# ---------- Load JSON ----------
with open(json_file, 'r', encoding='utf-8') as f:
    data = json.load(f)

# ---------- Severity mapping ----------
severity_mapping = {
    "information": 2,
    "notice": 3,
    "warning": 5,
    "error": 7,
    "critical": 10,
    "alert": 7       # Alert mapped like Error
}

# ---------- Helper to escape XML ----------
def xml_escape(text):
    if text is None:
        return ""
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&apos;"))

# ---------- Generate Wazuh rules ----------
rules_xml = ['<group name="fortigate-rules">']

# Header rule (fixed)
header_rule_id = 100010
rules_xml.append(f'''    <rule id="{header_rule_id}" level="4">
        <decoded_as>fortinet-fortigate-firewall</decoded_as>
        <description>Fortigate messages grouped</description>
    </rule>''')

# Starting ID for regular rules
rule_id = header_rule_id + 1

for entry in data.get('entries', []):
    # Get Message ID, pad to 6 characters, make regex safe, and escape XML
    raw_logid = entry.get("Message ID") or ""
    logid = xml_escape(re.escape(raw_logid.zfill(6)))

    description = xml_escape(entry.get("Message Meaning") or "No description")
    
    # Normalize severity and map to Wazuh level
    raw_severity = entry.get("Severity", "").strip()
    severity = raw_severity.lower()
    level = severity_mapping.get(severity, 4)  # default 4 if unknown
    
    # Build group dynamically
    group_parts = []
    if entry.get("Type"):
        group_parts.append(f"fortios.event.{entry['Type'].lower()}")
    if entry.get("Category"):
        group_parts.append(f"fortios.category.{entry['Category'].lower()}")
    if severity in severity_mapping:
        group_parts.append(f"fortios.severity.{severity}")
    group = ",".join(group_parts)
    
    # Build the rule XML with <if_sid> pointing to header
    rule = f'''    <rule id="{rule_id}" level="{level}">
        <decoded_as>fortinet-fortigate-firewall</decoded_as>
        <if_sid>{header_rule_id}</if_sid>
        <!-- {logid} -->
        <field name="message_id">{logid}</field>
        <description>{description}</description>
        <group>{group}</group>
    </rule>'''
    
    rules_xml.append(rule)
    rule_id += 1  # Increment ID for the next rule

rules_xml.append('</group>')

# ---------- Write Wazuh XML ----------
with open(wazuh_rules_file, 'w', encoding='utf-8') as f:
    f.write("\n".join(rules_xml))

total_rules = rule_id - header_rule_id
print(f"Wazuh rules generated in '{wazuh_rules_file}' with {total_rules} rules (including header).")
