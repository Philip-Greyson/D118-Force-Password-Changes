# Script to flag all AD users directly inside a list of OUs to change their password at next logon.
# Does NOT change or reset anyone's current password, it only sets the "User must change password at next logon" flag (pwdLastSet = 0)
# Only looks at users directly in each listed OU, sub-OUs are NOT searched (SearchScope OneLevel)
# Needs the ActiveDirectory module (RSAT) and an account with rights to modify the users in the target OUs

#Load Required modules
Import-Module ActiveDirectory

#Parameters
$localLog = ".\adPasswordChangeLog.txt" # output log file of everything the script does
$constantOU = $Env:CONSTANT_OU_ENDING # the constant parts of our AD OU structure, essentially everything after our building level

# The OUs to process. Use the full distinguished name of each OU, one per line. Only users DIRECTLY inside each OU are flagged, not users in sub-OUs
$targetOUs = @(
    "OU=Staff,OU=Example,$constantOU"
)

# Safety switch. When $true, the script only logs who WOULD be flagged without changing anything in AD
# Run it once with $true and review the log, then change to $false to actually set the flags
$dryRun = $true

$skipDisabled = $true # if $true, disabled accounts are skipped since they can't log on anyway
$clearPasswordNeverExpires = $true # if $true, users with "Password never expires" will have that turned off so the flag can be set. If $false they are skipped with a warning
$clearCannotChangePassword = $true # if $true, users with "User cannot change password" will have that turned off so they are able to change it. If $false they are skipped with a warning
$excludedAccounts = @() # any samAccountNames that should never be flagged even if inside the OUs (service accounts, kiosk accounts, etc). Example: @("svc-papercut", "kiosk1")

$syncControllers = $true # if $true, force replication between the domain controllers at the end so the flag is everywhere right away
$syncServer = "D118-DIST-OFF" # the domain controller to run the repadmin sync from

$spacer = "--------------------------------------------------" # just a spacer for printing easily repeatedly


# Function to write a message to both the console and the log file, so we don't have to write every line twice
function Write-Log
{
    param ([string]$message)
    Write-Output $message # write to console
    $message | Out-File -FilePath $localLog -Append # write to the log file
}


# Start a fresh log file for this run (no -Append so it overwrites the previous run's log, and creates the file if it doesn't exist)
$startTime = Get-Date -Format "HH:mm:ss"
"INFO: Execution started at $startTime" | Out-File -FilePath $localLog
Write-Output "INFO: Execution started at $startTime"
if ($dryRun)
{
    Write-Log "INFO: dryRun is set to true, no accounts will actually be changed. Set `$dryRun = `$false to apply the changes"
}

$processedAccounts = @() # tracks accounts already handled, in case the same OU is listed twice so nobody gets processed twice

# counters for the summary at the end
$flaggedCount = 0
$alreadyFlaggedCount = 0
$skippedCount = 0
$errorCount = 0

foreach ($OUPath in $targetOUs)
{
    # print out a spacer and the OU header to console and log file
    Write-Log $spacer
    Write-Log "STARTING OU: $OUPath"
    Write-Log $spacer

    # get every user directly in this OU. OneLevel means only the OU itself, not any sub-OUs beneath it
    # pwdLastSet tells us if the flag is already set (0 = must change at next logon), the others are used to decide if we should skip the user
    try
    {
        $ouUsers = Get-ADUser -Filter * -SearchBase $OUPath -SearchScope OneLevel -Properties pwdLastSet,PasswordNeverExpires,CannotChangePassword,Enabled,pSuDCID -ErrorAction Stop
    }
    catch
    {
        Write-Log "ERROR: Could not get the users in OU $OUPath, skipping this OU. Check that the distinguished name is correct"
        Write-Log $_ # write out the actual error
        $errorCount++
        continue # move on to the next OU in the list
    }

    $userCount = @($ouUsers).Count # wrap in @() so the count is correct even if there is only 1 or 0 users
    Write-Log "INFO: Found $userCount users directly in $OUPath"

    foreach ($adUser in $ouUsers)
    {
        $samAccountName = $adUser.SamAccountName
        $dcid = $adUser.pSuDCID

        if ($processedAccounts -contains $samAccountName) # already handled this person from a duplicate OU entry
        {
            continue
        }
        $processedAccounts += $samAccountName

        # skip any accounts that are in the exclusion list
        if ($excludedAccounts -contains $samAccountName)
        {
            Write-Log "INFO: Skipping $samAccountName because it is in the excluded accounts list"
            $skippedCount++
            continue
        }

        # skip disabled accounts if that option is on
        if ($skipDisabled -and !$adUser.Enabled)
        {
            Write-Log "DBUG: Skipping $samAccountName because the account is disabled"
            $skippedCount++
            continue
        }

        # no need to send an update if the flag is already set. pwdLastSet of 0 is what AD uses for "must change password at next logon"
        if ($adUser.pwdLastSet -eq 0)
        {
            Write-Log "DBUG: $samAccountName already has the change password flag set"
            $alreadyFlaggedCount++
            continue
        }

        # users with "User cannot change password" would get stuck unable to log on if forced to change it, so either turn it off first or skip the user
        $needsCannotChangeCleared = $false
        if ($adUser.CannotChangePassword)
        {
            if ($clearCannotChangePassword)
            {
                $needsCannotChangeCleared = $true # remember to clear it right before setting the flag below
            }
            else
            {
                Write-Log "WARN: Skipping $samAccountName because they have 'User cannot change password' set and would be locked out. Set `$clearCannotChangePassword = `$true to include them"
                $skippedCount++
                continue
            }
        }

        # AD will not let the flag be set while "Password never expires" is on, so either turn it off first or skip the user
        $needsNeverExpiresCleared = $false
        if ($adUser.PasswordNeverExpires)
        {
            if ($clearPasswordNeverExpires)
            {
                $needsNeverExpiresCleared = $true # remember to clear it right before setting the flag below
            }
            else
            {
                Write-Log "WARN: Skipping $samAccountName because they have 'Password never expires' set. Set `$clearPasswordNeverExpires = `$true to include them"
                $skippedCount++
                continue
            }
        }

        # if it is a dry run, just log what would happen without making the change
        if ($dryRun)
        {
            if ($needsCannotChangeCleared -and $needsNeverExpiresCleared)
            {
                Write-Log "INFO: DRY RUN - would turn of BOTH 'never expires' and 'cannot change' for $samAccountName, check for service account"
            }
            elseif ($needsCannotChangeCleared)
            {
                Write-Log "INFO: DRY RUN - would turn off 'User cannot change password' for $samAccountName"
                # Write-Log "INFO: DRY RUN - would turn off 'User cannot change password' for $dcid"
            }
            elseif ($needsNeverExpiresCleared)
            {
                Write-Log "INFO: DRY RUN - would turn off 'Password never expires' for $samAccountName"
                # Write-Log "INFO: DRY RUN - would turn off 'Password never expires' for $dcid"
            }
            Write-Log "INFO: DRY RUN - would flag $samAccountName to change password at next logon"
            # Write-Log "INFO: DRY RUN - would flag $dcid to change password at next logon"
            $flaggedCount++
            continue
        }
 
        # actually make the changes on the account
        try
        {
            if ($needsCannotChangeCleared)
            {
                Write-Log "ACTION - CANNOT CHANGE: Turning off 'User cannot change password' for $samAccountName"
                Set-ADUser $adUser -CannotChangePassword $false -ErrorAction Stop # removes the deny permission so the user is allowed to change their own password
            }
            if ($needsNeverExpiresCleared)
            {
                Write-Log "ACTION - NEVER EXPIRES: Turning off 'Password never expires' for $samAccountName"
                Set-ADUser $adUser -PasswordNeverExpires $false -ErrorAction Stop # has to be off before the change at logon flag can be set
            }
            Write-Log "ACTION - PASSWORD FLAG: Flagging $samAccountName to change password at next logon"
            Set-ADUser $adUser -ChangePasswordAtLogon $true -ErrorAction Stop # sets pwdLastSet to 0, the password itself is not touched
            $flaggedCount++
        }
        catch
        {
            Write-Log "ERROR: Could not set the change password flag on $samAccountName"
            Write-Log $_ # write out the actual error
            $errorCount++
        }
    }
}

# print out a summary of the run
Write-Log $spacer
if ($dryRun)
{
    $flaggedLabel = "Would be flagged" # change the wording of the summary depending on if it was a dry run
}
else
{
    $flaggedLabel = "Flagged"
}
Write-Log "INFO: $flaggedLabel : $flaggedCount | Already flagged: $alreadyFlaggedCount | Skipped: $skippedCount | Errors: $errorCount"

# synchronize the controllers so they all have the updated flags right away, only if we actually changed something
if ($syncControllers -and !$dryRun -and ($flaggedCount -gt 0))
{
    Write-Log "INFO: Forcing replication between domain controllers from $syncServer"
    repadmin.exe /syncall $syncServer /Aed
}

$endTime = Get-Date -Format "HH:mm:ss"
Write-Log "INFO: Execution ended at $endTime"
