"""Phase 5: JSON report -> Excel conversion (requires pandas + openpyxl)."""
import json
import os

from shadow_scanner.config import PANDAS_AVAILABLE, pd
def json_to_excel(input_file, output_file):
    """Converts JSON report to Excel format. Accepts full or relative paths."""
    if not PANDAS_AVAILABLE:
        print("\n[!] Pandas not installed. Skipping Excel conversion.")
        return

    input_path  = input_file  if os.path.isabs(input_file)  else os.path.join(os.getcwd(), input_file)
    output_path = output_file if os.path.isabs(output_file) else os.path.join(os.getcwd(), output_file)

    print(f"\n[PHASE 5] Excel Conversion → {output_path}")

    if not os.path.exists(input_path):
        print(f"  [X] ERROR: Input file '{input_path}' not found.")
        return

    try:
        with open(input_path, 'r') as f:
            data = json.load(f)

        endpoints = data.get('endpoints', []) if isinstance(data, dict) else data
        rows = []

        for item in endpoints:
            params = item.get('parameters', [])
            params_formatted = ", ".join(params) if isinstance(params, list) else str(params)

            rows.append({
                "Endpoint": item.get('endpoint', ''),
                "Method": item.get('method', 'GET'),
                "Parameters": params_formatted,
                "Source File": item.get('source', 'Unknown'),
                "Type": item.get('type', ''),
                "Classification": item.get('classification', ''),
                "Confidence": item.get('confidence_score', '')
            })

        df = pd.DataFrame(rows)

        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='API_Endpoints')
            worksheet = writer.sheets['API_Endpoints']
            # openpyxl is guaranteed importable here: ExcelWriter(engine='openpyxl')
            # above would already have failed without it.
            from openpyxl.utils import get_column_letter
            for column in df:
                col_idx = df.columns.get_loc(column) + 1
                worksheet.column_dimensions[get_column_letter(col_idx)].width = 25

        print(f"  [+] SUCCESS! Created: {output_file}")

    except Exception as e:
        print(f"  [X] ERROR Converting to Excel: {str(e)}")
