param([string]$Asm, [string]$TypeName, [string]$MethodName)
$a = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($Asm))
$mod = $a.ManifestModule
$t = $a.GetTypes() | Where-Object { $_.Name -eq $TypeName } | Select-Object -First 1
$m = $t.GetMethods("Public,NonPublic,Static,Instance,DeclaredOnly") | Where-Object { $_.Name -eq $MethodName } | Select-Object -First 1
$il = $m.GetMethodBody().GetILAsByteArray()
$ops = [System.Reflection.Emit.OpCodes].GetFields() | ForEach-Object { $_.GetValue($null) }
$by1 = @{}; $by2 = @{}
foreach ($o in $ops) { if ($o.Value -ge 256) { $by2[[int]($o.Value -band 0xFF)] = $o } else { $by1[[int]$o.Value] = $o } }
$i = 0
while ($i -lt $il.Length) {
  $b = [int]$il[$i]
  if ($b -eq 0xFE) { $op = $by2[[int]$il[$i+1]]; $tl = 2 } else { $op = $by1[$b]; $tl = 1 }
  if (-not $op) { $i++; continue }
  $ot = $op.OperandType.ToString()
  $sz = switch -regex ($ot) { 'InlineNone' {0} 'ShortInline.*' {1} '^InlineVar$' {2} 'InlineI8' {8} 'InlineR' {8} 'InlineSwitch' {-4} default {4} }
  if ($sz -gt 0 -and $ot -match 'InlineMethod|InlineField|InlineType|InlineTok|InlineString|InlineSig') {
    $tok = [BitConverter]::ToUInt32($il, $i + $tl)
    $name = ""
    try { $mem = $mod.ResolveMember($tok); if ($mem) { $name = $mem.Name } else { $name = "<null>" } } catch { $name = "<throw>" }
    if ($name -eq "" -or $name -eq "<null>" -or $name -eq "<throw>") {
      Write-Output ("  +" + $i + " " + $op.Name + " tok=0x" + $tok.ToString("X8") + " name=[" + $name + "]")
    }
  }
  $i += $tl + [Math]::Max($sz, 0)
}
Write-Output "scan done"
