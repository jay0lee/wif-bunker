# win_dialog_accept.ps1 — Background process for CI that auto-clicks
# Windows "Security Warning" dialogs and captures screenshots.
#
# Usage (launch as background job before running wif_bunker.py):
#   Start-Process powershell -ArgumentList "-NoProfile -File .github\scripts\win_dialog_accept.ps1" -NoNewWindow
#
# Based on the SendKeys pattern from GAM's ssd.mjs:
#   https://github.com/GAM-team/GAM/blob/main/src/tools/ssd.mjs

param(
    [int]$TimeoutSeconds = 120,
    [string]$ScreenshotDir = $env:GITHUB_WORKSPACE
)

if (-not $ScreenshotDir) { $ScreenshotDir = $PWD }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Take-Screenshot($label) {
    try {
        $screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
        if ($screen.Width -eq 0) { return }
        $bmp = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $bmp.Size)
        $path = Join-Path $ScreenshotDir "$label.png"
        $bmp.Save($path)
        Write-Host "  Screenshot: $path"
        $g.Dispose()
        $bmp.Dispose()
    } catch {
        Write-Host "  Screenshot failed: $_"
    }
}

Write-Host "Dialog auto-accept started (timeout: ${TimeoutSeconds}s)"
Write-Host "Screenshots will be saved to: $ScreenshotDir"

$wshell = New-Object -ComObject wscript.shell
$elapsed = 0
$clickCount = 0

while ($elapsed -lt $TimeoutSeconds) {
    $found = $wshell.AppActivate('Security Warning')
    if ($found) {
        $clickCount++
        Write-Host "Dialog #$clickCount found at ${elapsed}s"
        Take-Screenshot "dialog_${clickCount}_found"

        # Small delay to ensure the window is fully focused
        Start-Sleep -Milliseconds 500

        # Tab to the Yes button and press Enter
        $wshell.SendKeys('{TAB}{ENTER}')
        Write-Host "  Sent Tab+Enter"

        Start-Sleep -Milliseconds 500
        Take-Screenshot "dialog_${clickCount}_after_click"

        # Don't exit — there may be a second dialog (CA removal).
        # Just keep polling.
    }

    Start-Sleep -Seconds 1
    $elapsed++
}

Take-Screenshot "dialog_final"
Write-Host "Dialog auto-accept finished ($clickCount dialog(s) clicked in ${elapsed}s)"
