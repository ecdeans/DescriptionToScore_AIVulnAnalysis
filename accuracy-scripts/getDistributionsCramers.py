import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from scipy.stats import chi2_contingency
from glob import glob

# source: https://github.com/manindersingh120996/chi2_and_CrammerV_Corelation/blob/main/CrammerV_Correlation_with_each_variable_with_other_variable.py
def cramers_v(x, y):
    confusion_matrix = pd.crosstab(x, y)
    try:
        chi2 = chi2_contingency(confusion_matrix)[0]
        n = confusion_matrix.sum().sum()
        phi2 = chi2/n
        r, k = confusion_matrix.shape
        phi2corr = max(0, phi2-((k-1)*(r-1))/(n-1))
        rcorr = r-((r-1)**2)/(n-1)
        kcorr = k-((k-1)**2)/(n-1)
        return np.sqrt(phi2corr/min((kcorr-1),(rcorr-1)))
    except:
        return np.nan

def analyze_cve_data(base_path):
    # List to store all DataFrames
    all_dfs = []

    # Find all CSV files recursively two levels deep file structure: all_scraped/year/file.csv
    csv_files = glob(os.path.join(base_path, '**', '*.csv'), recursive=True)

    if not csv_files:
        print(f"No CSV files found in: {base_path}")
        return

    # Load all CSV files
    for file in csv_files:
        # This was added to try and find the source of missing description values
        try:
            df = pd.read_csv(file)
            df['__source_file__'] = file  # For file path
            df['__source_row__'] = df.index  # For row number
            all_dfs.append(df)
        except Exception as e:
            print(f"Error loading {file}: {e}")

    if not all_dfs:
        print("No valid data loaded from any CSV file")
        return
    
    # Combine all data
    combined_df = pd.concat(all_dfs, ignore_index=True)
    
    # Create output directory
    output_dir = os.path.join(base_path, 'analysis_results')
    os.makedirs(output_dir, exist_ok=True)

    def standardize_metric(df, column, possible_values):
        if column in df.columns:
            # Convert to uppercase and strip
            df[column] = df[column].astype(str).str.upper().str.strip()
            # Find closest match for each value
            standardized = []
            for val in df[column]:
                matched = False
                for pv in possible_values:
                    if str(val) == pv:
                        standardized.append(pv)
                        matched = True
                        break
                if not matched:
                    standardized.append(np.nan)
            df[column] = standardized
        return df

    # Define metrics with all possible values
    metric_specs = {
        'Attack Vector': {
            'values': ['NETWORK', 'ADJACENT_NETWORK', 'LOCAL', 'PHYSICAL'],
            'title': 'Attack Vector Distribution',
            'color': ['green', 'blue', 'purple', 'pink']
        },
        'Attack Complexity': {
            'values': ['LOW', 'HIGH'],
            'title': 'Attack Complexity Distribution',
            'color': 'lightcoral'
        },
        'Privileges Required': {
            'values': ['NONE', 'LOW', 'HIGH'],
            'title': 'Privileges Required Distribution',
            'color': 'lightgreen'
        },
        'User Interaction': {
            'values': ['NONE', 'REQUIRED'],
            'title': 'User Interaction Distribution',
            'color': 'gold'
        },
        'Scope': {
            'values': ['UNCHANGED', 'CHANGED'],
            'title': 'Scope Distribution',
            'color': 'violet'
        },
        'Confidentiality Impact': {
            'values': ['NONE', 'LOW', 'HIGH'],
            'title': 'Confidentiality Impact Distribution',
            'color': 'orange'
        },
        'Integrity Impact': {
            'values': ['NONE', 'LOW', 'HIGH'],
            'title': 'Integrity Impact Distribution',
            'color': 'pink'
        },
        'Availability Impact': {
            'values': ['NONE', 'LOW', 'HIGH'],
            'title': 'Availability Impact Distribution',
            'color': 'lightblue'
        },
        # Commented out for correlation of base metrics
        'Severity': {
            'values': ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
            'title': 'Severity Distribution',
            'color': ['green', 'yellow', 'orange', 'red', 'darkred']
        },
    }

    # Standardize all metric values
    for metric, specs in metric_specs.items():
        combined_df = standardize_metric(combined_df, metric, specs['values'])

    # Analysis functions
    def plot_metric_distributions():
        for metric, specs in metric_specs.items():
            if metric in combined_df.columns:
                plt.figure(figsize=(10, 6))
                
                # Get counts ensuring all possible values are represented
                counts = combined_df[metric].value_counts()
                # Reindex with all possible values to ensure none are missing
                counts = counts.reindex(specs['values'], fill_value=0)
                
                # Create bar plot
                if metric == 'Severity':
                    counts.plot(kind='bar', color=specs['color'])
                else:
                    counts.plot(kind='bar', color=specs['color'])
                
                plt.title(specs['title'])
                plt.xlabel(metric)
                plt.ylabel('Count')
                
                # Add percentage labels (only if >0 to avoid clutter)
                total = counts.sum()
                for i, v in enumerate(counts):
                    if v > 0:  # Only label bars with values
                        plt.text(i, v + 0.01*total, f'{v/total:.1%}\n({v})', ha='center')
                
                plt.xticks(rotation=45, ha='right')
                ymax = counts.max() * 1.15  # 15% higher than tallest bar
                plt.ylim(0, ymax)
                plt.tight_layout()
                
                # Save with high DPI to ensure readability
                plt.savefig(os.path.join(output_dir, f'{metric.replace(" ", "_")}_distribution.png'), 
                          dpi=300, bbox_inches='tight')
                plt.close()
                
                # Print actual counts for verification
                print(f"\n{metric} Distribution:")
                print(counts.to_string())
    
    def plot_description_lengths():
        combined_df['Description_Length'] = combined_df['Description'].str.len()

        # From when I was trying to find missing descriptions
        missing_mask = combined_df['Description'].isna()
        empty_mask = combined_df['Description'].astype(str).str.strip() == ''
        problem_rows = combined_df[missing_mask | empty_mask]
        print(f"Rows with missing or empty Description: {len(problem_rows)}")
        if not problem_rows.empty:
            print("Sample problematic rows (file, row, and first 100 chars):")
            for idx, row in problem_rows.head(10).iterrows():
                print(f"File: {row.get('__source_file__','?')}, Row: {row.get('__source_row__','?')}, Description: {str(row['Description'])[:100]!r}")

        # Debug print for number of descriptions being processed
        print(f"Processed {combined_df['Description_Length'].notna().sum()} descriptions for length analysis.")
        
        # Plot overall distribution
        plt.figure(figsize=(10, 6))
        plt.hist(combined_df['Description_Length'], bins=50, color='lightgreen', edgecolor='black')
        plt.title('Description Length Distribution')
        plt.xlabel('Number of Characters')
        plt.ylabel('Frequency')
        plt.grid(True, alpha=0.3)
        
        # Add vertical line at mean
        mean_len = combined_df['Description_Length'].mean()
        plt.axvline(mean_len, color='red', linestyle='--', 
                    label=f'Mean: {mean_len:.0f} chars')
        plt.legend()
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'description_length_distribution.png'), dpi=300)
        plt.close()
    
    def plot_correlations():
        metrics = list(metric_specs.keys())
        
        # Create correlation matrix
        corr_matrix = pd.DataFrame(index=metrics, columns=metrics)
        for var1 in metrics:
            for var2 in metrics:
                if var1 in combined_df.columns and var2 in combined_df.columns:
                    corr_matrix.loc[var1, var2] = cramers_v(combined_df[var1], combined_df[var2])
        
        corr_matrix = corr_matrix.astype(float)
        
        # Plot heatmap
        plt.figure(figsize=(12, 10))
        sns.heatmap(corr_matrix, annot=True, cmap='coolwarm', vmin=0, vmax=1, fmt=".2f",
                   cbar_kws={'label': "Correlation (Cramér's V)"})
        plt.title("Base Metric Correlations")
        plt.xticks(rotation=30, ha='right')
        plt.yticks(rotation=0)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'metrics_correlation.png'), dpi=300)
        plt.close()
    
    # Call functions
    plot_metric_distributions()
    plot_description_lengths()
    plot_correlations()
    
    print(f"\nDone. Results saved to: {output_dir}")

if __name__ == "__main__":
    base_path = "filepath"
    analyze_cve_data(base_path)