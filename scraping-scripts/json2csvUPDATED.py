import os
import json
import csv

def extract_data_from_json(file_path):
    """
    Extracts relevant CVE information from a new JSON file format.

    Parameters:
        file_path (str): The path to the JSON file.

    Returns:
        list: A list containing Description, Vendor, Product, Severity, Attack Complexity, Attack Vector, 
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
        
        # Extract vendor and product from the first element in the "affected" list
        affected = cna.get("affected", [])
        vendor = "N/A"
        product = "N/A"
        if affected:
            vendor = affected[0].get("vendor", "N/A")
            product = affected[0].get("product", "N/A")

        # Reject entry if vendor or product is not found
        if vendor == "N/A" or product == "N/A":
            return None
        
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

        # Exclude entries missing a "Severity"
        if baseSeverity == "N/A":
            return None

        # Exclude entries missing either "Attack Complexity" or "Attack Vector"
        if attackComplexity == "N/A" or attackVector == "N/A":
            return None
        
        return [description, vendor, product, baseSeverity, attackComplexity, attackVector, 
                availabilityImpact, confidentialityImpact, integrityImpact, privilegesRequired, 
                scope, userInteraction]
    
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None

def process_json_folder(folder_path, output_csv):
    headers = ["Description", "Vendor", "Product", "Severity", "Attack Complexity", "Attack Vector", 
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

# Example usage:
output_csv_file = "/Path/to/output/file.csv"
process_json_folder("Path/to/json/folder", output_csv_file)
