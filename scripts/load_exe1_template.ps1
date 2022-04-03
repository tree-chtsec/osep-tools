%libtransform%
%code%
$assem = [System.Reflection.Assembly]::Load($buf)
Function %function% { 
    [%class%]::Main($args) 
}
