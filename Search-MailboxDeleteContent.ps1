Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
$mailbox = Get-Content "C:\SCRIPTS\SearchMailboxDeleteContent\mailbox.txt"
foreach($box in $mailbox)
    {
        Search-Mailbox -Identity $box -DeleteContent -Force
    }