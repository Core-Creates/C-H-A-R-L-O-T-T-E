from core.logger import log_plugin_event

def run(args):
    file_path = args.get("file")
    log_plugin_event("bin_strings", f"Running string analysis on {file_path}")
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
            strings = [s for s in content.decode('utf-8', errors='ignore').split('\n') if len(s) > 4]
            log_plugin_event("bin_strings", f"Found {len(strings)} strings in {file_path}")
            return strings
    except Exception as e:
        log_plugin_event("bin_strings", f"Error processing {file_path}: {e}")
        return []
