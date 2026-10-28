"""Downloader and unpacker for Mordor Security Datasets."""

from __future__ import annotations

import io
import json
import logging
import urllib.request
import zipfile
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("mordor_downloader")

DATASETS = {
    "empire_launcher_vbs": {
        "url": "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/execution/host/empire_launcher_vbs.zip",
        "description": "Empire VBS Launcher & Stager Execution (MITRE T1059.005)",
    },
    "bitsadmin_download": {
        "url": "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/defense_evasion/host/cmd_bitsadmin_download_psh_script.zip",
        "description": "Living-off-the-land BITSAdmin Download Cradle (MITRE T1197)",
    },
    "empire_mimikatz_logonpasswords": {
        "url": "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip",
        "description": "Empire Mimikatz LogonPasswords LSASS Dump (MITRE T1003.001)",
    },
    "lsass_campaign_01": {
        "url": "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/compound/LSASS_campaign_01/metasploit_logonpasswords_lsass_memory_dump.zip",
        "description": "Compound Metasploit LSASS Memory Dump Campaign (MITRE T1003)",
    },
}


def download_and_extract(target_dir: Path) -> dict[str, Path]:
    """Downloads zip archives from GitHub raw, extracts JSON logs, and validates them."""
    target_dir.mkdir(parents=True, exist_ok=True)
    extracted_files: dict[str, Path] = {}

    for name, info in DATASETS.items():
        url = info["url"]
        desc = info["description"]
        logger.info("Downloading %s: %s", name, desc)

        req = urllib.request.Request(url, headers={"User-Agent": "ProvGraph-DFIR-Downloader/1.0"})
        try:
            with urllib.request.urlopen(req) as resp:
                content = resp.read()

            with zipfile.ZipFile(io.BytesIO(content)) as z:
                # Find json file in archive
                json_names = [n for n in z.namelist() if n.endswith(".json")]
                if not json_names:
                    logger.warning("No JSON file found in archive for %s", name)
                    continue

                for jname in json_names:
                    extracted_path = target_dir / Path(jname).name
                    with z.open(jname) as src_f, extracted_path.open("wb") as dst_f:
                        dst_f.write(src_f.read())

                    # Count records
                    rec_count = 0
                    with extracted_path.open("r", encoding="utf-8", errors="replace") as f:
                        first_char = f.read(1)
                        f.seek(0)
                        if first_char == "[":
                            data = json.load(f)
                            rec_count = len(data)
                        else:
                            for line in f:
                                if line.strip():
                                    rec_count += 1

                    size_kb = round(extracted_path.stat().st_size / 1024, 1)
                    logger.info(
                        "Extracted %s -> %s (%d events, %s KB)",
                        name,
                        extracted_path.name,
                        rec_count,
                        size_kb,
                    )
                    extracted_files[name] = extracted_path

        except Exception as e:
            logger.error("Failed to download %s from %s: %s", name, url, e)

    return extracted_files


if __name__ == "__main__":
    out_dir = Path(__file__).parent.parent / "data" / "raw_mordor"
    download_and_extract(out_dir)
