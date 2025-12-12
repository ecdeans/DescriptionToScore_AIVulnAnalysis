# AI-Vuln-Management
From Description to Score: Can LLMs Quantify Vulnerabilities?
==================================================

A project designed to enhance vulnerability management using LLMs (GPT-4o, GPT-5, Gemini-2.5-Flash, LLaMa-3.3-70B-Instruct,, DeepSeek-R1, and Grok-3). This tool leverages advanced AI models to analyze CVEs (Common Vulnerabilities and Exposures) and automatically score them using the CVSS v3.1 framework.

Table of Contents
-----------------
- Project Description
- Installation
- Usage
- Features
- Contact
- Future Work

Project Description
-------------------
Leveraging LLMs for Vulnerability Management is a Python-based tool that uses various AI models via Azure AI to interpret and score vulnerabilities automatically.

Goals:
- Provide expert knowledge needed for identifying vulnerabilities using LLMs.
- Enhance vulnerability management by using AI to automate vulnerability scoring and mitigation strategies.

Potential Impact:
- Reduces reliance on manual expertise for vulnerability assessment.
- Automates CVSS scoring to enhance efficiency.
- Strengthens cybersecurity by prioritizing threats intelligently.
- Improves workforce productivity in vulnerability management.

Installation
------------
1. Clone the repository:
   git clone https://github.com/yourusername/DescriptionToScore_AIVulnAnalysis.git
   cd DescriptionToScore_AIVulnAnalysis

2. Ensure you have Python 3.x installed.

3. Set up your environment variables with:
   - Azure AI API Key
   - Model Endpoint

4. Download CVE JSON files from:
   https://github.com/CVEProject/cvelistV5

5. Ensure you have a CSV viewer such as Excel installed.

Usage
-----
1. Place downloaded CVE JSON files in the appropriate folder.
2. Run the script:
   json2csvUPDATED.py
3. View output CSV files for results.
4. Place output file in the correct folder.
5. Run the script:
   2ex_descriptionOnly_scoring.py
6. View output CSV and Json files for results.

Features
--------
- Automatic CVSS v3.1 scoring using various AI Models
- Support for Azure AI API
- JSON input parsing and CSV output formatting
- Vulnerability analysis


Contact
-------
Daniel Thompson - danielthmpn@gmail.com,
Eva Deans - ecd7121@uncw.edu,
Sima Jafarikhah - jafarikhaht@uncw.edu

Future Work
-----------
- Augment descriptions with external context to better capture impact and improve model predictions
- Use fine-tuning on current models to improve decision-making
- Build AI-based vulnerability mitigation recommendations

Citation
-----------
If you use this repository or build upon our work, please cite the following paper:

    @inproceedings{jafarikhah2026vulnscoringllms,
      author    = {Sima Jafarikhah, Daniel Thompson, Eva Deans, Hossein Siadati and Yi Liu},
      title     = {From Description to Score: Can LLMs Quantify Vulnerabilities?},
      booktitle = {Proceedings of the 41st ACM/SIGAPP Symposium on Applied Computing (SAC 2026)},
      year      = {2026},
      address   = {Thessaloniki, Greece},
      publisher = {ACM},
      doi       = {10.1145/3748522.3779726}
    }
