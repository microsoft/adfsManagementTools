#Requires -Version 4
#Requires -RunAsAdministrator

<#

.SYNOPSIS
    Contains data gathering, health checks, and additional utilities for AD FS server deployments.

.DESCRIPTION

    Version: 1.0.0

    ADFSDiagnostics.psm1 is a Windows PowerShell module for diagnosing issues with ADFS


.DISCLAIMER
    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
    ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE.

    Copyright (c) Microsoft Corporation. All rights reserved.
#>


#Get public and private function definition files.
Write-Debug "ADFSDiagnostics: Importing public and private functions";

$Public  = @(Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue)
#Dot source the files
foreach($import in @($Public + $Private))
{
    try
    {
        Write-Debug "Verifying authenticode signature of $($import.fullname)";
        if((Get-AuthenticodeSignature $import.fullname).Status -eq "Valid")
        {
            . $import.fullname
        }
        else
        {
            Write-Error -Message "Failed to import $($import.fullname) because the authenticode signature was not valid.";
        }
    }
    catch
    {
        Write-Error -Message "Failed to import script $($import.fullname): $_"
    }
}

Export-ModuleMember -Function $Public.Basename