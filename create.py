import os
import random
import string
import time

# Define a folder with test data
desktop = os.path.join(os.path.expanduser("~"), "Desktop")
test_folder = os.path.join(desktop, "testFolder")
os.makedirs(test_folder, exist_ok=True)

suspicious_extensions = ['exe', 'bat', 'sh', 'dll', 'js', 'vbs']

# Function to generate normal files
def generate_normal_file(file_path, file_size_kb=10, file_type='txt'):
    if file_type == 'txt':
        content = ''.join(random.choices(string.ascii_letters + string.digits + ' \n', k=1024 * file_size_kb))
    elif file_type == 'js':
        content = ''.join(random.choices(string.ascii_letters + string.digits + ';\n{}()=', k=1024 * file_size_kb))
        content = f"// Generated JS File\n{content}"
    else:
        content = ''.join(random.choices(string.ascii_letters + string.digits, k=1024 * file_size_kb))

    mode = 'w'
    with open(file_path, mode) as f:
        f.write(content)

    print(f"Normal {file_type.upper()} file created: {file_path}")


# Function to generate suspicious files
def generate_suspicious_file(file_path, file_size_kb=10):
    extension = random.choice(suspicious_extensions)
    full_path = f"{file_path}.{extension}"
    content = os.urandom(1024 * file_size_kb)
    with open(full_path, 'wb') as f:
        f.write(content)
    print(f"Suspicious file created: {full_path}")


for i in range(10):
    generate_normal_file(os.path.join(test_folder, f"normal_file_{i + 1}.txt"), file_size_kb=10, file_type='txt')

for i in range(10):
    generate_normal_file(os.path.join(test_folder, f"normal_file_{i + 1}.js"), file_size_kb=10, file_type='js')

for i in range(10):
    generate_suspicious_file(os.path.join(test_folder, f"suspicious_file_{i + 1}"), file_size_kb=10)

# Verify metadata for all files
def print_file_metadata(file_path):
    stats = os.stat(file_path)
    print(f"File: {file_path}")
    print(f"  Size: {stats.st_size} bytes")
    print(f"  Created: {time.ctime(stats.st_ctime)}")
    print(f"  Modified: {time.ctime(stats.st_mtime)}")
    print(f"  Accessed: {time.ctime(stats.st_atime)}")


for file_name in os.listdir(test_folder):
    print_file_metadata(os.path.join(test_folder, file_name))

