import json
import os

def extract_analysis(ai_response_file, output_analysis_file, output_summary_file):
    with open(ai_response_file, 'r') as f:
        response = json.load(f)

    content = response.get('choices', [{}])[0].get('message', {}).get('content', '')
    
    with open(output_analysis_file, 'w') as f:
        f.write(content)

    # Extract one-line summaries and overall result
    one_line_summaries = []
    overall_result = ""

    for line in content.splitlines():
        if " — " in line:
            one_line_summaries.append(line)
        else:
            overall_result = line  # Assuming the last line is the overall result

    with open(output_summary_file, 'w') as f:
        f.write("---- ONE-LINE SUMMARIES ----\n")
        for summary in one_line_summaries:
            f.write(summary + "\n")
        f.write("---- OVERALL ----\n")
        f.write(overall_result + "\n")

if __name__ == "__main__":
    ai_response_json_path = 'ai_response.json'
    analysis_output_path = 'analysis.txt'
    summary_output_path = 'summary.txt'

    extract_analysis(ai_response_json_path, analysis_output_path, summary_output_path)