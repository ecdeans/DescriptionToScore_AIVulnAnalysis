# import json
import os
from openai import AzureOpenAI
from openai import OpenAIError
import csv
import time

api_key = "APIKEY" 
azure_endpoint = "ENDPOINT" 
api_version = "APIVERSION"

# Initialize Azure OpenAI client
client = AzureOpenAI(
    api_key=api_key,
    api_version=api_version,
    azure_endpoint=azure_endpoint,
)

def generate_vector_and_scores(cve_descriptions):
    max_retries = 5
    delay = 5  # Initial delay

    prompt = f""" 
    You are a cybersecurity expert specializing in analyzing CVE descriptions to determine CVSS v3.1 Base Scores. Your task involves:  
    
    ### Step 1. Extracting Metrics  
    From each CVE description, identify the following 9 metrics:  
    
    - Attack Vector: NETWORK, ADJACENT_NETWORK, LOCAL, PHYSICAL 
    - Attack Complexity: LOW, HIGH 
    - Privileges Required: NONE, LOW, HIGH 
    - User Interaction: NONE, REQUIRED 
    - Scope: UNCHANGED, CHANGED 
    - Confidentiality Impact: NONE, LOW, HIGH 
    - Integrity Impact: NONE, LOW, HIGH 
    - Availability Impact: NONE, LOW, HIGH
    - Base Severity: NONE, LOW, MEDIUM, HIGH, CRITICAL
    
    ### Step 2. Output Findings  
    For each CVE, output your findings in the following format, separated by new lines: 
    Attack Complexity | Attack Vector | Privileges Required | User Interaction | Scope | Confidentiality Impact | Integrity Impact | Availability Impact | Base Severity

    Do NOT provide any additional commentary or detail. NEVER number your responses. 
    Output must strictly follow this format for each CVE, with each result on a new line:  
    "LOW | NETWORK | NONE | REQUIRED | CHANGED | LOW | LOW | NONE | MEDIUM
    HIGH | ADJACENT_NETWORK | NONE | NONE | UNCHANGED | HIGH | HIGH | HIGH | HIGH"  
    
    ### CVE Examples:  
    
    Example 1:
    CVE Description: Cross-site scripting vulnerability exists in Splunk Config Explorer versions prior to 1.7.16. If this vulnerability is exploited, an arbitrary script may be executed on the web browser of the user who is using the product. 
    Attack Complexity: LOW 
    Attack Vector: NETWORK 
    Privileges Required: NONE 
    User Interaction: REQUIRED 
    Scope: CHANGED 
    Confidentiality Impact: LOW 
    Integrity Impact: LOW 
    Availability Impact: NONE 
    Base Severity: MEDIUM
    Output: LOW | NETWORK | NONE | REQUIRED | CHANGED | LOW | LOW | NONE | MEDIUM
    
    Example 2:
    CVE Description: An issue in the API wait function of NASA AIT-Core v2.5.2 allows attackers to execute arbitrary code via supplying a crafted string. 
    Attack Complexity: HIGH 
    Attack Vector: ADJACENT_NETWORK 
    Privileges Required: NONE 
    User Interaction: NONE 
    Scope: UNCHANGED 
    Confidentiality Impact: HIGH 
    Integrity Impact: HIGH 
    Availability Impact: HIGH
    Base Severity: HIGH
    Output: HIGH | ADJACENT_NETWORK | NONE | NONE | UNCHANGED | HIGH | HIGH | HIGH | HIGH
    """

    for i, description in enumerate(cve_descriptions, start=1):
        prompt += f"{i}. {description}\n"

    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert trained in analyzing CVE descriptions and generating their target variables, Attack Vector,  Attack Complexity,  Privileges Required, User Interaction, Scope, Confidentiality Impact, Integrity Impact, Availibility Impact, and  Base Severity."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0.2
            )

            generated_text = response.choices[0].message.content.strip()
            print(f"Generated text:\n {generated_text}")

            results = []
            for line in generated_text.split("\n"):
                if "|" in line:
                    parts = list(map(str.strip, line.split("|")))
                    if len(parts) == 9:
                        (attack_complexity, attack_vector, priv_required, user_interaction, 
                         scope, conf_impact, integ_impact, avail_impact, base_severity) = parts
                        results.append((attack_complexity, attack_vector, priv_required, user_interaction, 
                                        scope, conf_impact, integ_impact, avail_impact, base_severity))

            print(f"Extracted Results:\n {results}")
            return results
        
        except OpenAIError as e:
            if "429" in str(e):
                print(f"Rate limit hit. Retrying in {delay} seconds...")
                time.sleep(delay)
                delay *= 2
            else:
                print(f"OpenAI API error: {e}")
                break
    return []

def process_csv(input_file, output_file, batch_size=20):
    rows = []
    try:
        with open(input_file, mode='r', newline='', encoding='utf-8') as infile:
            csv_reader = csv.DictReader(infile)
            header = csv_reader.fieldnames + ['Generated Attack Complexity', 'Generated Attack Vector', 
                                              'Generated Privileges Required', 'Generated User Interaction',
                                              'Generated Scope', 'Generated Confidentiality Impact',
                                              'Generated Integrity Impact', 'Generated Availability Impact', 'Generated Severity']

            cve_descriptions = []
            row_batch = []

            for row in csv_reader:
                cve_description = row['Description']
                cve_descriptions.append(cve_description)
                row_batch.append(row)

                if len(cve_descriptions) == batch_size:
                    results = generate_vector_and_scores(cve_descriptions)
                    
                    for i, (ac, av, pr, ui, scope, ci, ii, ai, bs) in enumerate(results):
                        if i < len(row_batch):
                            row_batch[i]['Generated Attack Complexity'] = ac.upper()
                            row_batch[i]['Generated Attack Vector'] = av.upper()
                            row_batch[i]['Generated Privileges Required'] = pr.upper()
                            row_batch[i]['Generated User Interaction'] = ui.upper()
                            row_batch[i]['Generated Scope'] = scope.upper()
                            row_batch[i]['Generated Confidentiality Impact'] = ci.upper()
                            row_batch[i]['Generated Integrity Impact'] = ii.upper()
                            row_batch[i]['Generated Availability Impact'] = ai.upper()
                            row_batch[i]['Generated Severity'] = bs.upper()
                    rows.extend(row_batch)
                    cve_descriptions = []
                    row_batch = []

            if cve_descriptions:
                results = generate_vector_and_scores(cve_descriptions)
                for i, (ac, av, pr, ui, scope, ci, ii, ai, bs) in enumerate(results):
                    row_batch[i]['Generated Attack Complexity'] = ac.upper()
                    row_batch[i]['Generated Attack Vector'] = av.upper()
                    row_batch[i]['Generated Privileges Required'] = pr.upper()
                    row_batch[i]['Generated User Interaction'] = ui.upper()
                    row_batch[i]['Generated Scope'] = scope.upper()
                    row_batch[i]['Generated Confidentiality Impact'] = ci.upper()
                    row_batch[i]['Generated Integrity Impact'] = ii.upper()
                    row_batch[i]['Generated Availability Impact'] = ai.upper()
                    row_batch[i]['Generated Severity'] = bs.upper()
                rows.extend(row_batch)

        with open(output_file, mode='w', newline='', encoding='utf-8') as outfile:
            csv_writer = csv.DictWriter(outfile, fieldnames=header)
            csv_writer.writeheader()
            csv_writer.writerows(rows)

        print(f"Output saved to {output_file}")
        return rows  # return the processed rows
    except FileNotFoundError:
        print(f"Error: The input file '{input_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
        return rows

# # Function to convert processed CSV into individual JSON files
# def process_json(rows, output_folder):
#     try:
#         # Create the output folder if not exists
#         if not os.path.exists(output_folder):
#             os.makedirs(output_folder)

#         # Loop through each row (CVE) and create a JSON file
#         for row in rows:
#             cve_json = {
#                 "CVE_ID": row.get('CVE ID'),
#                 "Description": row.get('Description'),
#                 "Attributes": {
#                     "Base_Severity": {
#                         "Original": row.get('Base Severity'),
#                         "Generated": row.get('Generated Base Severity')
#                     },
#                     "Attack_Complexity": {
#                         "Original": row.get('Attack Complexity'),
#                         "Generated": row.get('Generated Attack Complexity')
#                     },
#                     "Attack_Vector": {
#                         "Original": row.get('Attack Vector'),
#                         "Generated": row.get('Generated Attack Vector')
#                     },
#                     "Privileges_Required": {
#                         "Original": row.get('Privileges Required'),
#                         "Generated": row.get('Generated Privileges Required')
#                     },
#                     "User_Interaction": {
#                         "Original": row.get('User Interaction'),
#                         "Generated": row.get('Generated User Interaction')
#                     },
#                     "Scope": {
#                         "Original": row.get('Scope'),
#                         "Generated": row.get('Generated Scope')
#                     },
#                     "Confidentiality_Impact": {
#                         "Original": row.get('Confidentiality Impact'),
#                         "Generated": row.get('Generated Confidentiality Impact')
#                     },
#                     "Integrity_Impact": {
#                         "Original": row.get('Integrity Impact'),
#                         "Generated": row.get('Generated Integrity Impact')
#                     },
#                     "Availability_Impact": {
#                         "Original": row.get('Availability Impact'),
#                         "Generated": row.get('Generated Availability Impact')
#                     }
#                 }
#             }

#             # Write JSON to file
#             output_file = os.path.join(output_folder, f"CVE_{row.get('CVE ID')}_scored.json")
#             with open(output_file, 'w', encoding='utf-8') as json_out:
#                 json.dump(cve_json, json_out, ensure_ascii=False, indent=4)

#             print(f"Saved JSON for {row.get('CVE ID')} to {output_file}")
#     except Exception as e:
#         print(f"An error occurred during JSON processing: {e}")

def main():
    input_directory = os.path.expanduser('FILEPATH')  
    output_directory = os.path.expanduser('FILEPATH')  

    os.makedirs(output_directory, exist_ok=True)  # Creates output dir if it doesn't exist

    for filename in os.listdir(input_directory):
        if filename.endswith('.csv'):
            input_file = os.path.join(input_directory, filename)

            name_part = os.path.splitext(filename)[0]
            output_file = os.path.join(output_directory, f"scored_{name_part}.csv")

            print(f"Processing: {input_file}")
            process_csv(input_file, output_file, batch_size=20)
    
    # Removed JSON logic
    # rows = process_csv(input_file, output_file, batch_size=20)
    # process_json(rows, "FILEPATH/scored_jsons")

if __name__ == "__main__":
    main()

