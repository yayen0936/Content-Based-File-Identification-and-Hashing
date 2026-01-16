import os
import shutil
import hashlib
import csv
import magic
 
# Configuration
SOURCE_DIR = './Lab2_Corpus'
OUTPUT_DIR = './triaged_files'
REPORT_NAME = 'triage_summary.csv'
 
# Define categories based on MIME types or magic strings
CATEGORY_MAP = {
    'application/x-dosexec': 'executables',
    'application/x-executable': 'executables',
    'application/pdf': 'documents',
    'application/msword': 'documents',
    'text/plain': 'textdocs',
    'text/x-python': 'scripts',
    'application/x-sh': 'scripts',
    'image/jpeg': 'images',
    'image/png': 'images',
    'application/zip': 'archives',
}
 
def calculate_hash(file_path):
    """Generates a SHA256 hash for a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()
 
def triage_files():
    # Ensure output directories exist
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
 
    report_data = []
 
    # Walk through the directory
    for root, dirs, files in os.walk(SOURCE_DIR):
        for filename in files:
            file_path = os.path.join(root, filename)
            # 1. Identify true file type using magic bytes
            # We use mime=True to get a clean string like 'application/pdf'
            file_mime = magic.from_file(file_path, mime=True)
            file_description = magic.from_file(file_path) # Human readable description
            # 2. Generate Hash
            file_hash = calculate_hash(file_path)
            # 3. Determine Category and detect mismatches
            extension = os.path.splitext(filename)[1].lower()
            category = CATEGORY_MAP.get(file_mime, 'other')
            # Logic for "Notes" / Mismatch detection
            notes = ""
            if extension == ".exe" and "text" in file_mime:
                notes = "Mismatched extension (Text masquerading as EXE)"
            elif extension != "" and extension not in file_mime and category == 'other':
                notes = "Potential mismatch or unknown type"
 
            # 4. Sort files into folders
            target_folder = os.path.join(OUTPUT_DIR, category)
            os.makedirs(target_folder, exist_ok=True)
            shutil.copy(file_path, os.path.join(target_folder, filename))
 
            # Add to report list
            report_data.append({
                'Original Filename': filename,
                'True File Type': file_mime,
                'Description': file_description,
                'Hash (SHA256)': file_hash,
                'Notes': notes
            })
 
    # 5. Produce Summary Report
    with open(REPORT_NAME, 'w', newline='') as csvfile:
        fieldnames = ['Original Filename', 'True File Type', 'Description', 'Hash (SHA256)', 'Notes']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report_data)
 
    print(f"Triage complete. Report saved to {REPORT_NAME}")
 
if __name__ == "__main__":
    triage_files()