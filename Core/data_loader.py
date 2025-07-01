# ============================================================================
# core/data_loader.py
# Handles loading and parsing data files used by CHARLOTTE
# ============================================================================

import os
import json
import xml.etree.ElementTree as ET

def load_json_file(filepath):
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            return json.load(f)
    return {}

def parse_xml_file(filepath):
    if os.path.exists(filepath):
        tree = ET.parse(filepath)
        return tree.getroot()
    return None