# Public launcher: this script and bootstrap.enc are the ONLY two public files.
# No token, private owner/repo, or package key is stored in plaintext here.
# Run using: powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File .\Start.ps1
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO.Compression

function Get-MasterPassword {
    $f = New-Object Windows.Forms.Form
    $f.Text = 'Unlock Private Packages'
    $f.Size = New-Object Drawing.Size(485, 166)
    $f.StartPosition = 'CenterScreen'
    $f.FormBorderStyle = 'FixedDialog'
    $f.MaximizeBox = $false; $f.MinimizeBox = $false; $f.TopMost = $true
    $label = New-Object Windows.Forms.Label
    $label.Text = 'Master password (paste with Ctrl+V):'
    $label.AutoSize = $true; $label.Location = New-Object Drawing.Point(14, 12)
    $f.Controls.Add($label)
    $inputBox = New-Object Windows.Forms.TextBox
    $inputBox.Location = New-Object Drawing.Point(14, 36)
    $inputBox.Size = New-Object Drawing.Size(445, 24)
    $inputBox.UseSystemPasswordChar = $true
    $inputBox.ShortcutsEnabled = $true
    $f.Controls.Add($inputBox)
    $ok = New-Object Windows.Forms.Button
    $ok.Text = 'Unlock'; $ok.Location = New-Object Drawing.Point(257, 80)
    $ok.DialogResult = [Windows.Forms.DialogResult]::OK
    $f.Controls.Add($ok); $f.AcceptButton = $ok
    $cancel = New-Object Windows.Forms.Button
    $cancel.Text = 'Cancel'; $cancel.Location = New-Object Drawing.Point(360, 80)
    $cancel.DialogResult = [Windows.Forms.DialogResult]::Cancel
    $f.Controls.Add($cancel); $f.CancelButton = $cancel
    try {
        $f.ActiveControl = $inputBox
        if ($f.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { throw 'Cancelled.' }
        if ($inputBox.TextLength -eq 0) { throw 'Password cannot be blank.' }
        $pw = ConvertTo-SecureString -String $inputBox.Text -AsPlainText -Force
        $inputBox.Clear()
        return $pw
    }
    finally { $inputBox.Clear(); $f.Dispose() }
}
function ConvertTo-PlainSecret([Security.SecureString]$Secure) {
    $ptr = [IntPtr]::Zero
    try {
        $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    } finally { if ($ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) } }
}
function Assert-EqualTag([byte[]]$Expected, [byte[]]$Actual) {
    if ($Expected.Length -ne $Actual.Length) { return $false }
    $diff = 0
    for ($i=0; $i -lt $Expected.Length; $i++) { $diff = $diff -bor ([int]$Expected[$i] -bxor [int]$Actual[$i]) }
    return ($diff -eq 0)
}
function Open-SealedBundle([string]$Path, [Security.SecureString]$Secret) {
    $blob = [IO.File]::ReadAllBytes($Path)
    if ($blob.Length -lt 84 -or $blob.Length -gt 20MB -or
        [Text.Encoding]::ASCII.GetString($blob, 0, 4) -cne 'BND1' -or
        (($blob.Length - 68) % 16) -ne 0) {
        throw 'Invalid encrypted bootstrap bundle.'
    }
    $length = $blob.Length - 32
    $salt = New-Object byte[] 16; $iv = New-Object byte[] 16
    [Buffer]::BlockCopy($blob, 4, $salt, 0, 16)
    [Buffer]::BlockCopy($blob, 20, $iv, 0, 16)
    $password = ConvertTo-PlainSecret $Secret
    $kdf = $null; $all = $null; $encKey = $null; $macKey = $null
    $aes = $null; $hmac = $null; $decryptor = $null
    try {
        $kdf = [Security.Cryptography.Rfc2898DeriveBytes]::new(
            $password, $salt, 250000, [Security.Cryptography.HashAlgorithmName]::SHA256)
        $all = $kdf.GetBytes(64)
        $encKey = New-Object byte[] 32; $macKey = New-Object byte[] 32
        [Buffer]::BlockCopy($all, 0, $encKey, 0, 32)
        [Buffer]::BlockCopy($all, 32, $macKey, 0, 32)
        $hmac = [Security.Cryptography.HMACSHA256]::new($macKey)
        $tag = $hmac.ComputeHash($blob, 0, $length)
        $actual = New-Object byte[] 32
        [Buffer]::BlockCopy($blob, $length, $actual, 0, 32)
        if (-not (Assert-EqualTag $tag $actual)) { throw 'Incorrect master password or damaged/tampered bootstrap.enc.' }
        $aes = [Security.Cryptography.Aes]::Create()
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $encKey; $aes.IV = $iv
        $decryptor = $aes.CreateDecryptor()
        $cipherSize = $length - 36
        $plain = $decryptor.TransformFinalBlock($blob, 36, $cipherSize)
        return ,$plain
    }
    finally {
        $password = $null
        if ($decryptor) { $decryptor.Dispose() }
        if ($hmac) { $hmac.Dispose() }
        if ($aes) { $aes.Dispose() }
        if ($kdf) { $kdf.Dispose() }
        if ($all) { [Array]::Clear($all,0,$all.Length) }
        if ($encKey) { [Array]::Clear($encKey,0,$encKey.Length) }
        if ($macKey) { [Array]::Clear($macKey,0,$macKey.Length) }
    }
}
function Expand-PrivateBootstrap([byte[]]$ZipBytes, [string]$Folder) {
    # Only known files are accepted, and no archive-controlled paths are used.
    $required = @('Bootstrap.ps1','PackageDecrypt.ps1','TokenCrypto.ps1',
                  'config.json','github-token.enc','package-password.enc')
    $seen = @{}
    $ms = [IO.MemoryStream]::new($ZipBytes, $false)
    $archive = $null
    try {
        $archive = [IO.Compression.ZipArchive]::new($ms,[IO.Compression.ZipArchiveMode]::Read,$true)
        if ($archive.Entries.Count -ne $required.Count) { throw 'Encrypted bootstrap has unexpected files.' }
        foreach ($entry in $archive.Entries) {
            if ($entry.FullName -cnotin $required -or $seen.ContainsKey($entry.FullName) -or $entry.Length -gt 5MB) {
                throw "Unexpected entry in encrypted bundle: $($entry.FullName)"
            }
            $seen[$entry.FullName] = $true
            $sourceStream = $entry.Open()
            $destStream = $null
            try {
                $destStream = [IO.File]::Create((Join-Path $Folder $entry.FullName))
                $sourceStream.CopyTo($destStream)
            }
            finally {
                if ($destStream) { $destStream.Dispose() }
                $sourceStream.Dispose()
            }
        }
        foreach ($file in $required) { if (-not $seen.ContainsKey($file)) { throw "Missing private bundle file: $file" } }
    }
    finally {
        if ($archive) { $archive.Dispose() }
        $ms.Dispose()
    }
}

$root = $PSScriptRoot
$encrypted = Join-Path $root 'bootstrap.enc'
if (-not (Test-Path -LiteralPath $encrypted -PathType Leaf)) {
    throw "bootstrap.enc missing beside Start.ps1 in $root. Download BOTH public files first."
}
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$secure = $null; $zipBytes = $null
$temp = Join-Path ([IO.Path]::GetTempPath()) ('private-bootstrap-' + [Guid]::NewGuid().ToString('N'))
try {
    $secure = Get-MasterPassword
    Write-Host 'Unlocking encrypted bootstrap...' -ForegroundColor Cyan
    $zipBytes = Open-SealedBundle -Path $encrypted -Secret $secure
    [void][IO.Directory]::CreateDirectory($temp)
    Expand-PrivateBootstrap -ZipBytes $zipBytes -Folder $temp
    Write-Host "Private bundle unlocked. Packages will be downloaded beside Start.ps1: $root" -ForegroundColor Green
    & (Join-Path $temp 'Bootstrap.ps1') -MasterSecure $secure -OutputRoot $root
}
finally {
    if ($zipBytes) { [Array]::Clear($zipBytes, 0, $zipBytes.Length) }
    if ($secure) { $secure.Dispose() }
    if (Test-Path -LiteralPath $temp) {
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
