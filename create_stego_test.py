#!/usr/bin/env python3
"""
Script to create a test file with LSB steganography
This file will be detected by our forensic analysis system
"""

import numpy as np
from PIL import Image
import os

def create_stego_image():
    """Creates an image with detectable LSB steganography"""
    
    # Create a simple test image
    width, height = 200, 200
    
    # Generate a base image (gradient)
    img_array = np.zeros((height, width, 3), dtype=np.uint8)
    
    # Create a simple gradient
    for i in range(height):
        for j in range(width):
            img_array[i, j] = [
                int(255 * i / height),  # Rouge
                int(255 * j / width),   # Vert
                128                     # Constant blue
            ]
    
    # Modify LSB bits to simulate steganography
    # This will create anomalies detectable by our algorithm
    secret_message = "SECRET_DATA_HIDDEN_HERE" * 20  # Repeated message
    binary_message = ''.join(format(ord(c), '08b') for c in secret_message)
    
    # Modify LSBs of red channel
    bit_index = 0
    for i in range(height):
        for j in range(width):
            if bit_index < len(binary_message):
                # Modify LSB bit
                current_pixel = img_array[i, j, 0]
                # Clear LSB and set message bit
                new_pixel = (current_pixel & 0xFE) | int(binary_message[bit_index])
                img_array[i, j, 0] = new_pixel
                bit_index += 1
    
    # Add artificial noise to increase entropy
    noise = np.random.randint(-5, 5, (height, width, 3))
    img_array = np.clip(img_array.astype(int) + noise, 0, 255).astype(np.uint8)
    
    # Create PIL image
    img = Image.fromarray(img_array)
    
    # Add suspicious EXIF metadata
    exif_dict = {
        "0th": {
            256: width,
            257: height,
            272: "STEGANOGRAPHY_TOOL_V2.1",  # Suspicious name
            306: "2023:01:01 00:00:00",
        },
        "Exif": {
            36867: "2023:01:01 00:00:01",
            37521: "A" * 500,  # Abnormally long comment
        }
    }
    
    return img

def create_suspicious_text_file():
    """Creates a text file with text steganography"""
    content = """
    This is a normal text file with some content.
    
    However, there might be hidden information here.
    Look carefully at the spacing and invisible characters.
    
    Normal paragraph here with regular text content.
    Another line of text that seems completely normal.
    
    But wait... there's more than meets the eye!
    
    """ + "\x00" * 1000 + """
    
    End of file with suspicious padding above.
    """
    
    # Add invisible characters to simulate steganography
    stego_content = ""
    for char in content:
        stego_content += char
        # Occasionally add invisible characters
        if np.random.random() < 0.1:
            stego_content += "\u200B"  # Zero-width space
    
    return stego_content

def main():
    """Create test files"""
    
    # Create test folder if it doesn't exist
    test_dir = "/home/nicnac/Bureau/School/Sweden/Big Data Forensic/forensic-triage"
    os.makedirs(test_dir, exist_ok=True)
    
    # 1. Create image with steganography
    print("Creating image with LSB steganography...")
    stego_img = create_stego_image()
    img_path = os.path.join(test_dir, "hidden_message.png")
    stego_img.save(img_path)
    print(f"Image created: {img_path}")
    
    # 2. Create suspicious text file
    print("Creating text file with steganography...")
    stego_text = create_suspicious_text_file()
    text_path = os.path.join(test_dir, "suspicious_document.txt")
    with open(text_path, 'w', encoding='utf-8') as f:
        f.write(stego_text)
    print(f"Text file created: {text_path}")
    
    # 3. Create binary file with high entropy
    print("Creating suspicious binary file...")
    random_data = np.random.bytes(5000)  # Very random data
    # Add suspicious padding at the end
    suspicious_data = random_data + b'\x00' * 2000
    
    bin_path = os.path.join(test_dir, "high_entropy_file.dat")
    with open(bin_path, 'wb') as f:
        f.write(suspicious_data)
    print(f"Binary file created: {bin_path}")
    
    print("\n" + "="*50)
    print("TEST FILES CREATED SUCCESSFULLY!")
    print("="*50)
    print(f"Folder: {test_dir}")
    print("Files:")
    print("1. hidden_message.png - Image with LSB steganography")
    print("2. suspicious_document.txt - Text with invisible characters")
    print("3. high_entropy_file.dat - High entropy binary file")
    print("\nThese files should be detected as suspicious")
    print("by your forensic analysis system!")

if __name__ == "__main__":
    main()