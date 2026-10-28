# Mordor Raw Datasets

This directory holds raw Mordor dataset JSON telemetry logs and working SQLite databases.

Because the raw attack logs exceed GitHub's single-file size limit (some logs exceed 100 MB), raw datasets are excluded from version control.

## Downloading Datasets
To automatically download and unpack the benchmark datasets:

```powershell
python scripts/download_mordor.py
```

This will fetch the following atomic and compound scenarios:
1. `empire_launcher_vbs` (MITRE T1059.005)
2. `cmd_bitsadmin_download_psh_script` (MITRE T1197)
3. `empire_mimikatz_logonpasswords` (MITRE T1003.001)
4. `metasploit_logonpasswords_lsass_memory_dump` (MITRE T1003)
