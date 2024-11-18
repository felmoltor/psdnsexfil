<#
    .SYNOPSIS
    This funciton converts an integer in base 10 to a base 36. This function is extracted form https://ss64.com/ps/syntax-base36.html
    .PARAMETER Num
    This is the decimal number to convert to base 36
#>
function ConvertTo-Base36
{
    [CmdletBinding()]
    param ([parameter(valuefrompipeline=$true, HelpMessage="Integer number to convert")][int]$Num=0)
    $alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    do
    {
        $remainder = ($Num % 36)
        $char = $alphabet.substring($remainder,1)
        $base36Num = "$char$base36Num"
        $Num = ($Num - $remainder) / 36
    }
    while ($Num -gt 0)

    $base36Num
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
    $decNum
}

ConvertTo-Base36 -Num 466
ConvertFrom-base36 -base36Num "CY"