import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
from sklearn.metrics import (
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    roc_curve,
    auc,
)
from sklearn.preprocessing import label_binarize

# Define the target columns and their expected class options.
target_columns = [
    "Attack Complexity", "Attack Vector", "Privileges Required", 
    "User Interaction", "Scope", "Confidentiality Impact", 
    "Integrity Impact", "Availability Impact"
]

class_options = {
    "Attack Vector": ["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"],
    "Attack Complexity": ["LOW", "HIGH"],
    "Privileges Required": ["NONE", "LOW", "HIGH"],
    "User Interaction": ["NONE", "REQUIRED"],
    "Scope": ["UNCHANGED", "CHANGED"],
    "Confidentiality Impact": ["NONE", "LOW", "HIGH"],
    "Integrity Impact": ["NONE", "LOW", "HIGH"],
    "Availability Impact": ["NONE", "LOW", "HIGH"]
}

def process_csv(input_file):
    """Load the CSV file and validate that it has the required columns."""
    df = pd.read_csv(input_file)
    df.columns = df.columns.str.strip()
    generated_columns = [f"Generated {col}" for col in target_columns]
    if not all(col in df.columns for col in target_columns + generated_columns):
        raise ValueError(f"Input CSV {input_file} is missing required columns.")
    return df


def plot_confusion_matrix(df, variable, classes=None, save_path=None):
    """
    Generate and display a confusion matrix along with precision, recall, F1, and ROC AUC.
    """
    # Prepare true and predicted labels
    y_true = df[variable].astype(str).str.strip().str.upper()
    y_pred = df[f"Generated {variable}"].astype(str).str.strip().str.upper()

    # Determine class list
    if classes is None:
        classes = sorted(set(y_true.unique()) | set(y_pred.unique()))

    # Compute confusion matrix
    cm = confusion_matrix(y_true, y_pred, labels=classes)
    print(f"\nConfusion Matrix for {variable}:")
    print(pd.DataFrame(cm, index=classes, columns=classes))

    # Compute macro-averaged precision, recall, F1
    precision_macro = precision_score(y_true, y_pred, labels=classes, average='macro', zero_division=0)
    recall_macro = recall_score(y_true, y_pred, labels=classes, average='macro', zero_division=0)
    f1_macro = f1_score(y_true, y_pred, labels=classes, average='macro', zero_division=0)
    print(f"Precision (macro): {precision_macro:.4f}")
    print(f"Recall (macro):    {recall_macro:.4f}")
    print(f"F1 Score (macro):  {f1_macro:.4f}")

    # For ROC AUC, we need binary labels for positive class
    # Define positive class as the second entry in classes list
    if len(classes) == 2:
        pos = classes[1]
        y_true_b = (y_true == pos).astype(int)
        y_pred_b = (y_pred == pos).astype(int)
        # Compute binary ROC
        try:
            fpr, tpr, _ = roc_curve(y_true_b, y_pred_b)
            roc_auc_binary = auc(fpr, tpr)
            print(f"ROC AUC:           {roc_auc_binary:.4f}")
        except ValueError:
            roc_auc_binary = None
            print("ROC AUC:           could not compute (only one class present)")

        # Plot confusion matrix with metrics
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=classes, yticklabels=classes)
        plt.xlabel("Predicted")
        plt.ylabel("Actual")
        title = (
            f"{variable} Confusion Matrix\n"
            f"Precision={precision_macro:.2f}, Recall={recall_macro:.2f}, F1={f1_macro:.2f}"
        )
        if roc_auc_binary is not None:
            title += f", AUC={roc_auc_binary:.2f}"
        plt.title(title)
        if save_path:
            plt.savefig(save_path)
        plt.show()

        # Plot binary ROC curve if computed
        if roc_auc_binary is not None:
            plt.figure(figsize=(8, 6))
            plt.plot(fpr, tpr, label=f"AUC = {roc_auc_binary:.2f}")
            plt.plot([0, 1], [0, 1], 'k--')
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title(f"ROC Curve for {variable} (AUC = {roc_auc_binary:.2f})")
            plt.legend(loc='lower right')
            if save_path:
                base, ext = os.path.splitext(save_path)
                plt.savefig(f"{base}_{variable.replace(' ', '_')}_roc.png")
            plt.show()

    else:
        # Multiclass ROC AUC
        y_true_bin = label_binarize(y_true, classes=classes)
        y_pred_bin = label_binarize(y_pred, classes=classes)
        fpr = {}
        tpr = {}
        roc_auc = {}
        for i, cls in enumerate(classes):
            fpr[i], tpr[i], _ = roc_curve(y_true_bin[:, i], y_pred_bin[:, i])
            roc_auc[i] = auc(fpr[i], tpr[i])
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            roc_auc_macro = None
            try:
                roc_auc_macro = roc_auc_score(
                    y_true_bin, y_pred_bin, average='macro', multi_class='ovr'
                )
            except ValueError:
                pass
        if roc_auc_macro is None or pd.isna(roc_auc_macro):
            print("ROC AUC (macro):   could not compute (only one class present)")
            roc_auc_macro = None
        else:
            print(f"ROC AUC (macro):   {roc_auc_macro:.4f}")

        # Plot confusion matrix with metrics
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=classes, yticklabels=classes)
        plt.xlabel("Predicted")
        plt.ylabel("Actual")
        title = (
            f"{variable} Confusion Matrix\n"
            f"Precision={precision_macro:.2f}, Recall={recall_macro:.2f}, F1={f1_macro:.2f}"
        )
        if roc_auc_macro is not None:
            title += f", AUC={roc_auc_macro:.2f}"
        plt.title(title)
        if save_path:
            plt.savefig(save_path)
        plt.show()

        # Plot multiclass ROC curves if available
        if roc_auc_macro is not None:
            plt.figure(figsize=(8, 6))
            for i, cls in enumerate(classes):
                plt.plot(fpr[i], tpr[i], label=f"{cls} (AUC = {roc_auc[i]:.2f})")
            plt.plot([0, 1], [0, 1], 'k--', label='Chance')
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title(
                f"ROC Curve for {variable} (macro AUC = {roc_auc_macro:.2f})"
            )
            plt.legend(loc='lower right')
            if save_path:
                base, ext = os.path.splitext(save_path)
                plt.savefig(f"{base}_{variable.replace(' ', '_')}_roc.png")
            plt.show()


def main():
    # Parent directory containing only the specified year folders
    base_dir = os.path.expanduser(r"Path/to/input")  # adjust to your path
    png_dir = os.path.expanduser(r"Path/to/confusion_matrix/output")
    # Process these folders in this exact order
    year_folders = [
        "2005_scored", "2008_scored", "2010_scored", "2011_scored",
        "2012_scored", "2013_scored", "2014_scored", "2015_scored",
        "2016_scored", "2017_scored", "2018_scored", "2019_scored",
        "2020_scored", "2021_scored", "2022_scored", "2023_scored", 
        "2024_scored"
    ]

    combined_data = pd.DataFrame()
    total_cves_processed = 0
    accuracy_results = {col: {'correct': 0, 'total': 0} for col in target_columns}

    # Iterate through each folder in the specified order
    for folder in year_folders:
        folder_path = os.path.join(base_dir, folder)
        if not os.path.isdir(folder_path):
            print(f"Warning: folder not found: {folder_path}")
            continue
        print(f"\nProcessing folder: {folder}")
        for filename in os.listdir(folder_path):
            if filename.endswith(".csv"):
                input_file = os.path.join(folder_path, filename)
                try:
                    df = process_csv(input_file)
                except ValueError as e:
                    print(e)
                    continue

                total_cves = len(df)
                total_cves_processed += total_cves
                combined_data = pd.concat([combined_data, df], ignore_index=True)

                for col in target_columns:
                    gen_col = f"Generated {col}"
                    correct = (df[col].astype(str).str.upper() == df[gen_col].astype(str).str.upper()).sum()
                    accuracy_results[col]['correct'] += correct
                    accuracy_results[col]['total'] += total_cves

    # Optionally save combined CSV
    output_file = os.path.expanduser(r"Path/to/output/combined_data.csv")
    combined_data.to_csv(output_file, index=False)
    print(f"\nTotal CVEs processed across all years: {total_cves_processed}")

    # Generate one confusion matrix and ROC per variable across all data
    for variable in target_columns:
        classes = class_options.get(variable)
        print(f"\nGenerating combined metrics for {variable}...")
        save_path = os.path.join(png_dir, f"combined_{variable.replace(' ', '_')}.png")
        plot_confusion_matrix(combined_data, variable, classes=classes, save_path=save_path)

if __name__ == "__main__":
    main()
