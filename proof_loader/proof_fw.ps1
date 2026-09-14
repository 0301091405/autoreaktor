param([Parameter(Mandatory=$true)][string]$AsmPath)

$bytes = [System.IO.File]::ReadAllBytes($AsmPath)
try {
    $asm = [System.Reflection.Assembly]::Load($bytes)
    Write-Output ("LOADED: " + $asm.FullName)
    Write-Output ("RUNTIME: " + [System.Environment]::Version.ToString())
    $types = $asm.GetTypes()
    Write-Output ("TYPES: " + $types.Count)
    $methods = 0
    foreach ($t in $types) { $methods += $t.GetMethods([System.Reflection.BindingFlags]"Public,NonPublic,Instance,Static,DeclaredOnly").Count }
    Write-Output ("METHODS: " + $methods)
    $ep = $asm.EntryPoint
    if ($ep) { Write-Output ("ENTRYPOINT: " + $ep.Name + " ILSize=" + $ep.GetMethodBody().GetILAsByteArray().Length) }
    else { Write-Output "ENTRYPOINT: none (library)" }
    foreach ($t in $types) {
        foreach ($m in $t.GetMethods([System.Reflection.BindingFlags]"Public,NonPublic,Instance,Static,DeclaredOnly")) {
            if ($m.Name -match "Main|CheckReg|Register|Validate") {
                Write-Output ("CANDIDATE: " + $t.FullName + "::" + $m.Name)
            }
        }
    }
} catch {
    Write-Output ("LOAD-FAILED: " + $_.Exception.Message)
}
