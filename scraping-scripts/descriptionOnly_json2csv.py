import os
import json
import csv

def extract_data_from_json(file_path):
    """
    Extracts relevant CVE information from a new JSON file format.

    Parameters:
        file_path (str): The path to the JSON file.

    Returns:
        list: A list containing Description, Severity, Attack Complexity, Attack Vector, 
              Availability Impact, Confidentiality Impact, Integrity Impact, Privileges Required, Scope, 
              and User Interaction. Returns None if an error occurs or required fields are missing.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
        
        # Navigate to the "cna" container in the JSON structure.
        cna = data.get("containers", {}).get("cna", {})
        if not cna:
            return None
        
        # Extract the description from the "descriptions" list (first element with lang "en")
        description = "N/A"
        for desc in cna.get("descriptions", []):
            if desc.get("lang", "").lower() == "en":
                description = desc.get("value", "N/A")
                break
        
        # Extract CVSS metrics from the first element in the "metrics" list (using cvssV3_1)
        metrics = cna.get("metrics", [])
        cvss = {}
        if metrics:
            cvss = metrics[0].get("cvssV3_1", {})
        
        baseSeverity = cvss.get("baseSeverity", "N/A")
        attackComplexity = cvss.get("attackComplexity", "N/A")
        attackVector = cvss.get("attackVector", "N/A")
        availabilityImpact = cvss.get("availabilityImpact", "N/A")
        confidentialityImpact = cvss.get("confidentialityImpact", "N/A")
        integrityImpact = cvss.get("integrityImpact", "N/A")
        privilegesRequired = cvss.get("privilegesRequired", "N/A")
        scope = cvss.get("scope", "N/A")
        userInteraction = cvss.get("userInteraction", "N/A")

        # Defining a list of invalid values.
        invalid_values = ["", " ", "N/A"]

        # Check if any of the extracted values are in the invalid values list.
        if baseSeverity in invalid_values:
            return None

        # Additional checks for other variables.
        if (attackComplexity in invalid_values or 
            attackVector in invalid_values or 
            availabilityImpact in invalid_values or 
            confidentialityImpact in invalid_values or 
            integrityImpact in invalid_values or 
            privilegesRequired in invalid_values or 
            scope in invalid_values or 
            userInteraction in invalid_values):
            return None
        
        return [description, baseSeverity, attackComplexity, attackVector, 
                availabilityImpact, confidentialityImpact, integrityImpact, 
                privilegesRequired, scope, userInteraction]
    
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None

def process_json_folder(folder_path, output_csv):
    headers = ["Description", "Severity", "Attack Complexity", "Attack Vector", 
               "Availability Impact", "Confidentiality Impact", "Integrity Impact", "Privileges Required", 
               "Scope", "User Interaction"]
       
    with open(output_csv, 'w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(headers)
        
        for root, _, files in os.walk(folder_path):
            for file in files:
                if file.endswith(".json"):
                    file_path = os.path.join(root, file)
                    extracted_data = extract_data_from_json(file_path)
                    if extracted_data:
                        writer.writerow(extracted_data)

def main():
    # Define the base directory that contains multiple JSON folders.
    input_directory = '/Path/to/input/json/folders/'
    # Define the directory where you want to save the CSV files.
    output_directory = '/Path/to/output/directory'
    
    # List all items in the parent directory and filter only directories.
    folder_list = [folder for folder in os.listdir(input_directory)
                   if os.path.isdir(os.path.join(input_directory, folder))]
    
    for folder in folder_list:
        input_folder = os.path.join(input_directory, folder)
        # Create the output CSV file name as "cve_data{folder_name}.csv"
        output_csv_file = os.path.join(output_directory, f"cve_data{folder}.csv")
        print(f"Processing folder: {input_folder} -> {output_csv_file}")
        process_json_folder(input_folder, output_csv_file)

if __name__ == '__main__':
    main()
