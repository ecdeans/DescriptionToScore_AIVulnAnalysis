import os
import pandas as pd

# Define which columns to compare
target_columns = [
    "Severity", "Attack Complexity", "Attack Vector", "Privileges Required", "User Interaction", 
    "Scope", "Confidentiality Impact", "Integrity Impact", "Availability Impact"
]

# Function to load and validate a CSV file
def process_csv(input_file):
    df = pd.read_csv(input_file)
    df.columns = df.columns.str.strip()

    generated_columns = [f"Generated {col}" for col in target_columns]

    # Check if all required columns are present
    if not all(col in df.columns for col in target_columns + generated_columns):
        raise ValueError(f"Input CSV {input_file} is missing required columns.")
    
    return df 

def main():
    # Directory containing CSVs
    input_dir = os.path.expanduser("FILEPATH")
    output_file = os.path.expanduser("FILEPATH")

    total_cves_processed = 0
    combined_data = pd.DataFrame()
    accuracy_results = {col: {'correct': 0, 'total': 0} for col in target_columns}

    # Iterate over all .csv files in the specified directory
    for filename in os.listdir(input_dir):
        if filename.endswith(".csv"):
            input_file = os.path.join(input_dir, filename)

            try:
                df = process_csv(input_file)
            except ValueError as e:
                print(e)
                continue  # skip files with missing columns

            total_cves = len(df)
            total_cves_processed += total_cves
            combined_data = pd.concat([combined_data, df], ignore_index=True)

            # Accuracy calculation
            for col in target_columns:
                gen_col = f"Generated {col}"
                correct = (df[col] == df[gen_col]).sum()
                accuracy_results[col]['correct'] += correct
                accuracy_results[col]['total'] += total_cves

    # Save combined data
    combined_data.to_csv(output_file, index=False)

    # Build and print summary
    accuracy_summary = []
    for col in target_columns:
        correct = accuracy_results[col]['correct']
        total = accuracy_results[col]['total']
        percentage = (correct / total) * 100 if total > 0 else 0
        accuracy_summary.append({
            'Variable': col,
            'Correct': correct,
            'Accuracy': f"{percentage:.2f}%"
        })

    accuracy_df = pd.DataFrame(accuracy_summary)

    print("\nAccuracy Summary:")
    print(f"{'Variable':<25} {'Correct':<15} {'Accuracy':<10}")
    for _, row in accuracy_df.iterrows():
        print(f"{row['Variable']:<25} {row['Correct']:<15} {row['Accuracy']:<10}")

    print(f"\nTotal CVEs processed: {total_cves_processed}")

if __name__ == "__main__":
    main()
