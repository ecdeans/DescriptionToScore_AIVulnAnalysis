import os
import pandas as pd

def process_csv(input_file, output_file):
    df = pd.read_csv(input_file)

    # Check for needed columns
    required_columns = ["Base Score", "Generated Score", "Vector String", "Generated Vector String"]
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        raise ValueError(f"Input CSV is missing required columns: {', '.join(missing_columns)}")

    # Handle missing or "N/A" values for Base Scores
    def check_empty(value):
        try:
            return float(value)
        except (ValueError, TypeError):
            return None

    df["Base Score"] = df["Base Score"].apply(check_empty)
    df["Generated Score"] = df["Generated Score"].apply(check_empty)

    def compute_difference(row):
        # If there is a missing value
        if pd.isna(row["Base Score"]) or pd.isna(row["Generated Score"]):
            return "N/A"
        return abs(row["Base Score"] - row["Generated Score"])

    def categorize_accuracy(row):
        if row["Score Difference"] == "N/A":
            return "N/A"
        if row["Score Difference"] == 0:
            return "Accurate"
        elif row["Score Difference"] <= 0.5:
            return "Fairly Accurate"
        else:
            return "Inaccurate"

    df["Score Difference"] = df.apply(compute_difference, axis=1)
    df["Accuracy"] = df.apply(categorize_accuracy, axis=1)

    # Compare Vector Strings for exact match
    def compare_vectors(row):
        if pd.isna(row["Vector String"]) or pd.isna(row["Generated Vector String"]):
            return "N/A"
        elif row["Vector String"] == row["Generated Vector String"]:
            return "Correct"
        else:
            return "Incorrect"

    df["Vector Match"] = df.apply(compare_vectors, axis=1)

    df.to_csv(output_file, index=False)

    return df

# Main function to process files in the specified range
def main():
    all_data = []

    folder_num = 35
    while folder_num <= 47:
        input_file = os.path.expanduser(f'/Path/to/file/scored_cve_{folder_num}xxx.csv')  
        output_file = os.path.expanduser(f"/Path/to/file/accuracyVec_cve_{folder_num}xxx.csv")

        file_data = process_csv(input_file, output_file)

        all_data.append(file_data)

        folder_num += 1

    # Combine all data
    combined_df = pd.concat(all_data, ignore_index=True)

    # Final output file path for combined results
    final_output_file = os.path.expanduser("/Path/to/file/accuracyVec_cve_combined.csv")

    # Save the combined results
    combined_df.to_csv(final_output_file, index=False)

    # Print the counts for the aggregated results
    accuracy_counts = combined_df["Accuracy"].value_counts()
    vector_match_counts = combined_df["Vector Match"].value_counts()

    print("Accuracy Counts:")
    print(accuracy_counts)
    print("\nVector Match Counts:")
    print(vector_match_counts)

if __name__ == "__main__":
    main()

