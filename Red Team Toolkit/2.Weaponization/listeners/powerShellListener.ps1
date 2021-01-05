# Start listener on port 443
$listener = [System.Net.Sockets.TcpListener]443; $listener.Start();
 
while($true)
{
    $client = $listener.AcceptTcpClient();
    Write-Host $client.client.RemoteEndPoint "connected!";
    $client.Close();
    start-sleep -seconds 1;
}
