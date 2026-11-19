# Captures the Netcheck window and reports what the eye sees down the page (window pixels, 100 % scale):
#   TEXT = rows with letters (bright pixels), EDGE = rows where a card / tab-bar outline runs across the page.
param([string]$Label = "page", [int]$From = 40, [int]$To = 460)
Add-Type -AssemblyName System.Drawing
Add-Type -Namespace M -Name W -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
[DllImport("user32.dll")] public static extern bool GetWindowRect(System.IntPtr h, out RECT r);
[DllImport("user32.dll")] public static extern bool PrintWindow(System.IntPtr h, System.IntPtr dc, uint flags);
public struct RECT { public int L, T, R, B; }
'@
[M.W]::SetProcessDPIAware() | Out-Null
$h = [IntPtr](Get-Process Netcheck).MainWindowHandle
$r = New-Object M.W+RECT; [M.W]::GetWindowRect($h, [ref]$r) | Out-Null
$w = $r.R - $r.L; $ht = $r.B - $r.T
$bmp = New-Object System.Drawing.Bitmap $w, $ht
$g = [System.Drawing.Graphics]::FromImage($bmp); $dc = $g.GetHdc()
[M.W]::PrintWindow($h, $dc, 2) | Out-Null; $g.ReleaseHdc($dc); $g.Dispose()
$bmp.Save("$PSScriptRoot\shot-$Label.png")
function Sum($c) { $c.R + $c.G + $c.B }
$kinds = @{}
for ($y = $From; $y -le [Math]::Min($To, $ht - 2); $y++) {
    # letters: any clearly bright pixel in the middle 60 %
    $bright = 0
    for ($x = [int]($w * 0.2); $x -lt [int]($w * 0.8); $x += 2) { if ((Sum $bmp.GetPixel($x, $y)) -gt 420) { $bright++ } }
    # edge: a horizontal line = most sampled columns are brighter than the row 2 px above AND 2 px below
    $edge = 0; $n = 0
    for ($x = [int]($w * 0.1); $x -lt [int]($w * 0.9); $x += 8) {
        $n++; $s = Sum $bmp.GetPixel($x, $y)
        if ($s -gt (Sum $bmp.GetPixel($x, $y - 2)) + 18 -and $s -gt (Sum $bmp.GetPixel($x, $y + 2)) + 18) { $edge++ }
    }
    $kinds[$y] = if ($bright -gt 0) { 'TEXT' } elseif ($edge -gt $n * 0.35) { 'EDGE' } else { '' }
}
$bmp.Dispose()
# Collapse into runs and print with the clear space between them.
$out = @(); $cur = $null
for ($y = $From; $y -le [Math]::Min($To, $ht - 2); $y++) {
    $k = $kinds[$y]
    if ($k -and $cur -and $cur.Kind -eq $k -and $cur.To -ge $y - 1) { $cur.To = $y; continue }
    if ($k) { $cur = [pscustomobject]@{ Kind = $k; From = $y; To = $y }; $out += $cur }
}
$k = $w / 1134.0
"$Label  (physical ${w}x${ht}, scale {0:0.##}; numbers below in app px)" -f $k
$prev = $null
foreach ($o in $out) {
    $gap = if ($prev) { $o.From - $prev.To - 1 } else { '-' }
    "  {0,-4} {1,6:0.0}-{2,-6:0.0} space above: {3}" -f $o.Kind, ($o.From / $k), ($o.To / $k), $(if ($gap -is [int]) { "{0:0.0}" -f ($gap / $k) } else { $gap })
    $prev = $o
}
