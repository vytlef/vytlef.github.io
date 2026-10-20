param(
  [string]$OutDir = (Join-Path $PSScriptRoot "..\web\icons")
)

Add-Type -AssemblyName System.Drawing

function New-RoundedRectPath {
  param([float]$X, [float]$Y, [float]$W, [float]$H, [float]$R)
  $path = New-Object System.Drawing.Drawing2D.GraphicsPath
  $d = $R * 2
  $path.AddArc($X, $Y, $d, $d, 180, 90)
  $path.AddArc($X + $W - $d, $Y, $d, $d, 270, 90)
  $path.AddArc($X + $W - $d, $Y + $H - $d, $d, $d, 0, 90)
  $path.AddArc($X, $Y + $H - $d, $d, $d, 90, 90)
  $path.CloseFigure()
  return $path
}

function New-CryptoPicIcon {
  param([int]$Size, [string]$OutPath, [bool]$Maskable)

  $bmp = New-Object System.Drawing.Bitmap($Size, $Size)
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
  $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality

  $top = [System.Drawing.Color]::FromArgb(255, 96, 124, 255)
  $bot = [System.Drawing.Color]::FromArgb(255, 56, 86, 220)
  $corner = New-Object System.Drawing.Point(0, 0)
  $corner2 = New-Object System.Drawing.Point(0, $Size)
  $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($corner, $corner2, $top, $bot)

  if ($Maskable) {
    $g.FillRectangle($brush, 0, 0, $Size, $Size)
    $glyph = $Size * 0.54
  } else {
    $bgPath = New-RoundedRectPath 0 0 $Size $Size ($Size * 0.20)
    $g.FillPath($brush, $bgPath)
    $bgPath.Dispose()
    $glyph = $Size * 0.62
  }

  $cx = $Size / 2.0
  $gy = ($Size - $glyph) / 2.0

  $bodyW = $glyph * 0.70
  $bodyH = $glyph * 0.48
  $bodyX = $cx - $bodyW / 2.0
  $bodyY = $gy + $glyph * 0.44

  $bodyPath = New-RoundedRectPath $bodyX $bodyY $bodyW $bodyH ($bodyH * 0.24)
  $g.FillPath([System.Drawing.Brushes]::White, $bodyPath)
  $bodyPath.Dispose()

  $shW = $glyph * 0.46
  $shH = $glyph * 0.40
  $shX = $cx - $shW / 2.0
  $shY = $bodyY - $shH + $glyph * 0.04
  $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, ($glyph * 0.095))
  $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
  $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
  $g.DrawArc($pen, $shX, $shY, $shW, $shH * 2, 180, 180)
  $pen.Dispose()

  $khBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 74, 104, 242))
  $d = $glyph * 0.15
  $khCy = $bodyY + $bodyH * 0.40
  $g.FillEllipse($khBrush, $cx - $d / 2.0, $khCy - $d / 2.0, $d, $d)
  $stemW = $d * 0.50
  $stemH = $d * 1.15
  $stemPath = New-RoundedRectPath ($cx - $stemW / 2.0) ($khCy + $d * 0.10) $stemW $stemH ($stemW / 2.0)
  $g.FillPath($khBrush, $stemPath)
  $stemPath.Dispose()
  $khBrush.Dispose()

  $g.Dispose()
  $bmp.Save($OutPath, [System.Drawing.Imaging.ImageFormat]::Png)
  $bmp.Dispose()
  Write-Host "OK: $OutPath ($Size x $Size)"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

New-CryptoPicIcon -Size 192 -OutPath (Join-Path $OutDir "icon-192.png") -Maskable $false
New-CryptoPicIcon -Size 512 -OutPath (Join-Path $OutDir "icon-512.png") -Maskable $false
New-CryptoPicIcon -Size 512 -OutPath (Join-Path $OutDir "icon-maskable.png") -Maskable $true

Write-Host "Selesai. Ikon PWA di $OutDir"
