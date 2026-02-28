#  Inspectra

## Overview
 Inspectra is a comprehensive tool designed for auditing TLS endpoints. It automates the process of collecting endpoint data, performing SSL scans, and generating detailed reports on the security posture of the endpoints.

## Features
- **Endpoint Collection**: Extracts URLs from configuration files with specified extensions.
- **JDK Detection**: Identifies the Java Development Kit version and vendor in the environment.
- **SSL Scanning**: Performs SSL scans on collected endpoints using OpenSSL, retrieving certificate details, protocol versions, and cipher suites.
- **Java Release Fetching**: Fetches the latest Java releases from Oracle's website.
- **Prompt Construction**: Builds prompts for language models based on collected data.
- **Model Interaction**: Sends prompts to the GitHub Models API for analysis and retrieves results.
- **Analysis Extraction**: Processes model responses to derive summaries and overall results.
- **Report Generation**: Creates SARIF and Sonar files for code scanning and persists raw artifacts.

## Setup Instructions
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/vithminds-inspectra.git
   cd vithminds-inspectra
   ```

2. **Install Dependencies**:
   Ensure you have Python installed, then run:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure GitHub Actions**:
   The project includes a GitHub Actions workflow defined in `.github/workflows/inspectra.yaml`. This workflow can be triggered manually or on specific events.

## Usage
To run the TLS endpoint audit, you can trigger the GitHub Actions workflow from the GitHub interface or run the scripts locally as needed. Each script is designed to be modular, allowing for flexibility in execution.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
