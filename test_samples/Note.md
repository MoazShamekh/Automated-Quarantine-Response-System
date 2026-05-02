# Important Note
- These are harmless test files.
- After generating the hashes, add them to the default_signatures.txt file.
# How to GENERATE SHA-256 HASHES
## Use PowerShell
'''
Get-FileHash file_name.exe -Algorithm SHA256
Get-FileHash file_name.bat -Algorithm SHA256
'''
## Example output:
'''
Hash      : 9F1A...E23C
Path      : C:\av_real_samples\open_cmd.exe
'''
