# Digital Forensic Triage System

An automated file classification system for digital forensic analysis, based on academic research and industry best practices.

## Description

This project implements a forensic triage system that:
- Automatically analyzes uploaded files
- Classifies files according to their forensic potential
- Uses a 5-level scoring system inspired by Cyber Triage
- Detects suspicious, hidden, and potentially malicious files
- Provides a web interface for analysis and visualization

## Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

## Installation

### 1. Clone or download the project

```bash
cd "Big Data Forensic"
```

### 2. Create a virtual environment (recommended)

```bash
python3 -m venv forensic-env
source forensic-env/bin/activate  # On Linux/Mac
# or
forensic-env\Scripts\activate     # On Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

The installed dependencies are:
- Flask 2.3.3 (web framework)
- python-magic 0.4.27 (file type detection)
- pandas 2.0.3 (data analysis)
- Werkzeug 2.3.7 (web utilities)
- Pillow 10.0.0 (image processing)
- numpy 1.24.3 (numerical computations)

### 4. Install libmagic (if needed)

On Ubuntu/Debian:
```bash
sudo apt-get install libmagic1
```

On macOS:
```bash
brew install libmagic
```

On Windows:
```bash
# Usually included with python-magic
```

## Running the Application

### 1. Activate the virtual environment (if used)

```bash
source forensic-env/bin/activate  # On Linux/Mac
# or
forensic-env\Scripts\activate     # On Windows
```

### 2. Launch the application

```bash
python3 app.py
```

### 3. Access the web interface

Open your browser and go to:
```
http://localhost:5000
```

## Usage

1. **File Upload**: Drag and drop or select files to analyze
2. **Automatic Analysis**: The system analyzes each file and calculates a suspicion score
3. **Classification**: Files are classified into 5 levels:
   - **Level 5**: Very suspicious (red)
   - **Level 4**: Suspicious (orange)
   - **Level 3**: Moderately interesting (yellow)
   - **Level 2**: Less interesting (light blue)
   - **Level 1**: Not interesting (green)
4. **Visualization**: View results in the web interface with charts and statistics

## Testing the System

The project includes a test dataset in the `forensic-triage/` directory containing various types of files designed to demonstrate the system's capabilities:

- `malware.exe` - Suspicious executable file
- `encrypted.bin` - High-entropy encrypted file
- `hidden_message.png` - Image with potential steganographic content
- `high_entropy_file.dat` - File with high entropy data
- `suspicious_document.txt` - Text file with suspicious keywords
- `test.txt` - Normal text file for comparison

To test the system:
1. Launch the application as described above
2. Upload the entire `forensic-triage/` folder or individual files from it
3. Observe how different files are classified and scored
4. Review the detailed analysis results to understand the scoring criteria

## Project Structure

```
Big Data Forensic/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── templates/            # HTML templates
├── static/              # Static CSS/JS files
├── uploads/             # Uploaded files storage directory
├── forensic-env/        # Python virtual environment
└── README.md           # This file
```

## Features

### Forensic Analysis
- Hidden file detection (names starting with '.')
- Metadata analysis (size, dates, permissions)
- Steganography detection in images
- MIME type classification
- MD5 hash calculation for integrity

### Scoring System
- **Suspicion criteria**: Dangerous extensions, system files, etc.
- **Content analysis**: Suspicious pattern detection
- **Intelligent scoring**: Combination of multiple factors

### Web Interface
- Drag & drop upload
- Real-time visualization
- Interactive charts
- Results export

## Stopping the Application

To stop the application:
1. In the terminal, press `Ctrl+C`
2. Deactivate the virtual environment: `deactivate`

## Troubleshooting

### "ModuleNotFoundError" Error
```bash
# Check that virtual environment is activated
source forensic-env/bin/activate
pip install -r requirements.txt
```

### libmagic Error
```bash
# On Ubuntu/Debian
sudo apt-get install libmagic1 libmagic-dev

# On macOS
brew install libmagic
```

### Port Already in Use
If port 5000 is occupied, the application will automatically suggest an alternative port.

## Support

For any questions or issues, check:
1. That Python 3.7+ is installed: `python3 --version`
2. That all dependencies are installed: `pip list`
3. That the virtual environment is activated
4. That libmagic is installed on your system