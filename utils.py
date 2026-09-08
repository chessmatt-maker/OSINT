import json

def parse_ndjson(file_path):
    """
    Parses a Newline Delimited JSON (NDJSON) file into a standard Python list.
    Safely ignores empty lines or unparseable JSON blocks.
    """
    parsed_data = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():  # Skip empty lines
                    try:
                        parsed_data.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return parsed_data
    except FileNotFoundError:
        return {"error": f"File not found: {file_path}"}
    except Exception as e:
        return {"error": f"Error reading NDJSON: {str(e)}"}