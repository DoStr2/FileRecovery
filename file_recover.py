import win32file
import re
import shutil
import os
from PIL import Image
import logging
import string

DISK_SHUTIL = r"E:\\" #path to disk
DISK_WIN32 = r"\\.\E:" # path to disk

SIGNATURES = {

    b"\x89PNG\r\n\x1a\n": ("png", b"\x49\x45\x4E\x44\xAE\x42\x60\x82"),


    b"\xFF\xD8": ("jpg", b"\xFF\xD9"),


    b"%PDF": ("pdf", b"%%EOF"),


    b"\x50\x4B\x03\x04": ("zip", b"\x50\x4B\x05\x06"),


    b"\x52\x61\x72\x21\x1A\x07\x00": ("rar", b"\x00\x00\x00\x00"),


    b"\x52\x61\x72\x21\x1A\x07\x01\x00": ("rar5", b"\x00\x00\x00\x00"),


    b"GIF87a": ("gif", b"\x3B"),


    b"GIF89a": ("gif", b"\x3B"),


    b"\x50\x4B\x03\x04": ("docx", b"\x50\x4B\x05\x06"),

    b"\x50\x4B\x03\x04": ("xlsx", b"\x50\x4B\x05\x06"),


    b"\x50\x4B\x03\x04": ("pptx", b"\x50\x4B\x05\x06"),


}

BLOCK_SIZE = 256 # jump size by block

log_file = "recovery_log.txt"
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', filename=log_file,
                    filemode='a')
logger = logging.getLogger()


def read_raw_data():
    try:
        total_size = shutil.disk_usage(DISK_SHUTIL).total
        logger.info(f"Total disk size: {total_size} bytes")

        hDrive = win32file.CreateFile(
            DISK_WIN32,
            win32file.GENERIC_READ,
            win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
            None,
            win32file.OPEN_EXISTING,
            0,
            None,
        )

        raw_data = win32file.ReadFile(hDrive, total_size, None)[1]
        win32file.CloseHandle(hDrive)

        return raw_data
    except Exception as e:
        logger.error(f"Failed to read disk: {e}")
        return None


def find_deleted_files(raw_data, signatures):
    found_files = []
    used_ranges = []

    for start_sig, (ext, end_sig) in signatures.items():
        raw_data = bytearray(raw_data)

        start_matches = re.finditer(re.escape(start_sig), raw_data)
        for start_match in start_matches:
            start_index = start_match.start()

            end_matches = re.finditer(re.escape(end_sig), raw_data[start_index:])
            for end_match in end_matches:
                end_index = start_index + end_match.end()
                logger.info(f"Found deleted file {ext} at address: {start_index}-{end_index} bytes")
                found_files.append((start_index, end_index, ext))
                used_ranges.append((start_index, end_index))
                break

    return found_files, used_ranges


def check_image_validity(file_path):
    try:
        with Image.open(file_path) as img:
            img.verify()
        return True
    except (IOError, SyntaxError) as e:
        logger.error(f"Invalid image file: {e}")
        return False


def recover_file(raw_data, start, end, ext, output_directory="C:\\Users\\d9787\\Desktop\\Cyber\\recovered_files"):
    file_name = f"recovered_{start}.{ext}"
    path = os.path.join(output_directory, file_name)

    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "wb") as f:
        f.write(raw_data[start:end])

    if ext in ["png", "jpg"]:
        if check_image_validity(path):
            logger.info(f"File recovered and verified: {path}")
        else:
            logger.error(f"Recovered file is invalid: {path}")
            os.remove(path)


def is_text_data(data, threshold=0.9):
    if not data:
        return False
    printable_chars = set(string.printable.encode('utf-8'))
    text_chars = sum(1 for byte in data if byte in printable_chars)

    return (text_chars / len(data)) >= threshold


def recover_text_files(raw_data, used_ranges, output_directory="C:\\Users\\d9787\\Desktop\\Cyber\\recovered_files"):
    os.makedirs(output_directory, exist_ok=True)
    recovered_count = 0
    total_size = len(raw_data)


    used_ranges.sort()


    full_ranges = [(0, 0)] + used_ranges + [(total_size, total_size)]


    current_text_data = b""  #
    current_text_start = None

    for i in range(len(full_ranges) - 1):
        start = full_ranges[i][1]
        end = full_ranges[i + 1][0]

        if start < end:  #
            for offset in range(start, end, BLOCK_SIZE):
                chunk_end = min(offset + BLOCK_SIZE, end)
                chunk = raw_data[offset:chunk_end]

                if len(chunk) >= 100 and is_text_data(chunk):
                    if current_text_data == b"":
                        current_text_start = offset

                    current_text_data += chunk

                else:
                    if current_text_data:
                        file_path = os.path.join(output_directory, f"recovered_text_{recovered_count}.txt")
                        with open(file_path, "wb") as f:
                            f.write(current_text_data)
                        logger.info(f"Recovered text file: {file_path}")
                        recovered_count += 1


                        current_text_data = b""
                        current_text_start = None


    if current_text_data:
        file_path = os.path.join(output_directory, f"recovered_text_{recovered_count}.txt")
        with open(file_path, "wb") as f:
            f.write(current_text_data)
        logger.info(f"Recovered text file: {file_path}")




def run():
    raw_data = read_raw_data()
    if raw_data:
        found_files, used_ranges = find_deleted_files(raw_data, SIGNATURES)

        for start, end, ext in found_files:
            recover_file(raw_data, start, end, ext)


        recover_text_files(raw_data, used_ranges)
