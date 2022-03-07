function xor {
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Byte[]] $s,
        [Parameter(Position = 1)] [string] $key
    )
    [Byte[]] $b = new-object -TypeName Byte[] -ArgumentList @($s.Length);
    [Byte[]] $kb = [System.Text.Encoding]::ASCII.GetBytes($key);
    for($i=0; $i -lt $b.Length; $i++) {
        $b[$i] = ($s[$i] -bxor $kb[$i % $kb.length]) -band 0xff;
    }
    return $b;
}
function cae {
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Byte[]] $s,
        [Parameter(Position = 1)] [int] $key
    )
    [Byte[]] $b = new-object -TypeName Byte[] -ArgumentList @($s.Length);
    for($i=0; $i -lt $b.Length; $i++) {
        $b[$i] = ($s[$i] -$key) -band 0xff;
    }
    return $b;
}
function b64 {
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Byte[]] $s,
        [Parameter(Position = 1)] [int] $key
    )
    [System.Collections.Generic.List[Byte]] $g = New-Object System.Collections.Generic.List[Byte](,$s);
    for($i=0; $i -lt $key; $i++) {
        $g = new-object System.Collections.Generic.List[Byte](,[System.Convert]::FromBase64String([System.Text.Encoding]::ASCII.GetString($g.ToArray())));
    }
    return $g.ToArray();
}
