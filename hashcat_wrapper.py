import gzip
import json
import logging
import os
import shlex
import socket
import subprocess
import sys
import tarfile
import threading
from datetime import datetime, timedelta
import time
import requests

EXEC = "hashcat"
TMP_DIR = "/tmp"
NTFY_TOPIC = os.environ["NTFY_TOPIC"]
HASHCAT_ATTACK = os.environ["HASHCAT_ATTACK"]
WORKLOAD = "4"
DICT_URL = os.environ.get("DICT_URL")
WORDLIST_FILENAMES: list[str] = []
OUT_FILE = os.path.join(TMP_DIR, "hashcat.out")
UPDATE_INTERVAL = 10
STATUS = f"--quiet --status --status-json --status-timer={UPDATE_INTERVAL} --outfile {OUT_FILE}"
HASH_TARGET = None # Can be hash string or hashes file

DISABLE_NTFY = True if os.environ.get("DISABLE_NTFY", "").lower() == "true" else False

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s | %(levelname)s | %(message)s")


def send_ntfy(message: str):
    if DISABLE_NTFY:
        logging.debug(("NTFY: " + message))
    else:
        requests.post(f"https://ntfy.sh/{NTFY_TOPIC}",
                      headers={"content-type": "text/plain", "Title": "Hashcat updates"},
                      data=message.encode(encoding='utf-8'))


def save_file(content: bytes, filename: str):
    try:
        f = open(filename, "wb")
        f.write(content)
    except OSError as e:
        logging.error(f"Failed to write to file: {e}")
        raise


def handle_file(content: bytes, filename: str) -> str | list[str]:
    if filename.endswith(".gz"):
        try:
            gzip_f = gzip.open(filename)
            gzip_f.write(content)
        except gzip.BadGzipFile:
            logging.exception(f"Failed to gunzip file:")
        finally:
            gzip_f.close()

        filename = filename.replace(".gz", "")

    if filename.endswith(".tar"):
        try:
            tar_f = tarfile.open(content)
        except tarfile.TarError:
            logging.exception(f"Failed to untar file:")
            raise

        filenames = []
        for member in tar_f.getmembers():
            save_file(tar_f.extractfile(member).read(), member.name)
            filenames.append(member.name)

        tar_f.close()
        return filenames
    else:
        full_path = os.path.join(TMP_DIR, filename)
        save_file(content, full_path)
        return full_path


def handle_file_url(url: str) -> str | list[str]:
    try:
        resp = requests.get(url)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to download dictionary: {e}")
        raise

    return handle_file(resp.content, resp.url.split("/")[-1])


def execute_attack() -> int:
    cmd = f"{EXEC} -w{WORKLOAD} {STATUS} {HASH_TARGET} {HASHCAT_ATTACK}"
    logging.info(f"Execute command: {cmd}")
    try:
        p = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        start_time = last_time = datetime.now()

        for line in iter(p.stdout.readline, ""):
            p.poll()
            if p.returncode == 0:
                break
            elif p.returncode is not None:
                raise subprocess.SubprocessError
            try:
                status_dict = json.loads(line)
            except json.decoder.JSONDecodeError:
                continue
            logging.info(status_dict)

            time_now = datetime.now()
            delta = time_now - last_time
            if delta > timedelta(minutes=30):
                last_time = time_now
                # summarizing speed from all devices
                total_speed = 0
                for dev in status_dict['devices']:
                    total_speed += dev['speed']

                time_left = status_dict["estimated_stop"] - int(time_now.timestamp())
                send_ntfy(f"Running for: {(datetime.now() - start_time)} "
                          f"Speed: {total_speed} KHash/m. "
                          f"Estimated finish time left: {time_left} seconds"
                          f"Recovered: {len(status_dict['recovered_hashes'])} hashes")
            time.sleep(5)
    except subprocess.SubprocessError as e:
        logging.error(f"Command: '{cmd}' exits with return code: {p.returncode} Error: {p.stderr.readlines()}")
    finally:
        p.stdout.close()
        p.returncode

    return p.returncode


# thread to monitor resolved hashes
def monitor_output(stop_event: threading.Event):
    if not os.path.exists(OUT_FILE):
        with open(OUT_FILE, "w") as f:
            f.write("")

    with open(OUT_FILE, "r") as f:
        while not stop_event.is_set():
            line = f.readline()
            if line:
                send_ntfy(f"Found recovered hash: {line}")
            else:
                time.sleep(0.5)


def main() -> int:
    # Get targets
    global HASH_TARGET
    if len(sys.argv) > 1 and sys.argv[1]:
        logging.info(f"Received hash: {sys.argv[1]}")
        HASH_TARGET = sys.argv[1]
    else:
        hashes_url = os.environ.get("HASHES_URL")
        if hashes_url:
            logging.info(f"Downloading hashes from: '{hashes_url}'")
            HASH_TARGET = handle_file_url(hashes_url)
        else:
            logging.error()
            exit(2)

    if DICT_URL:
        logging.info(f"Downloading dictionary from: '{DICT_URL}'")
        global WORDLIST_FILENAMES
        WORDLIST_FILENAMES = handle_file_url(DICT_URL)

    stop_event = threading.Event()
    monitor_t = threading.Thread(target=monitor_output, args=(stop_event,))
    monitor_t.start()

    ret_code = execute_attack()
    # Stopping thread
    stop_event.set()
    monitor_t.join()

    return ret_code


if __name__ == "__main__":
    ntfy_status = "ntfy is disabled" if DISABLE_NTFY else ""
    logging.info(f"Starting Hashcat wrapper {ntfy_status}")
    send_ntfy(f"Finished on host {socket.gethostname()} (error code: {main()}")
