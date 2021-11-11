<!-- Description -->
## Description
With this HelloID Service Automation Delegated Form you can add mapping rules to a CSV for Nedap. The CSV contains rules in which AFAS Organisational Units are mapped to Nedap Locations. The following options are available:
 1. Select the mapping rule
 2. Change the mapped Nedap locations
 3. Confirm the changes

## Versioning
| Version | Description | Date |
| - | - | - |
| 1.0.1   | Added version number and updated all-in-one script | 2021/11/04  |
| 1.0.0   | Initial release | 2021/09/28  |

<!-- TABLE OF CONTENTS -->
## Table of Contents
* [Description](#description)
* [All-in-one PowerShell setup script](#all-in-one-powershell-setup-script)
  * [Getting started](#getting-started)
* [Pre-setup configuration](#pre-setup-configuration)
  * [Requirements](#requirements)
* [Post-setup configuration](#post-setup-configuration)
* [Manual resources](#manual-resources)


## All-in-one PowerShell setup script
The PowerShell script "createform.ps1" contains a complete PowerShell script using the HelloID API to create the complete Form including user defined variables, tasks and data sources.

 _Please note that this script asumes none of the required resources do exists within HelloID. The script does not contain versioning or source control_

### Getting started
Please follow the documentation steps on [HelloID Docs](https://docs.helloid.com/hc/en-us/articles/360017556559-Service-automation-GitHub-resources) in order to setup and run the All-in one Powershell Script in your own environment.

## Pre-setup configuration
These forms can only be used when Nedap ONS user provisioning is provided by HelloID provisioning and AFAS is your sourcesystem. Therefore it is also necessary that the files in which the organisational units are mapped with the locations and the teams are available on the server. These mapping files can be found in the [HelloID-Conn-Prov-Target-NedapONS-Users](https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-NedapONS-Users#helloid-conn-prov-target-nedapons-users).

Be aware that using Service Automation forms can have an impact on the licenses and impact the pay-as-you-go subscriptions! 

### Requirements
<table>
	<tr><td>AFAS as a sourcesystem within HelloID provisioning</td><tr>
	<tr><td>Nedap ONS users as a targetsystem within HelloID provisioning</td><tr>
	<tr><td>HelloID Service Automation license</td><tr>
</table>
 
 
## Post-setup configuration
After the all-in-one PowerShell script has run and created all the required resources. The following items need to be configured according to your own environment
 1. Update the following [user defined variables](https://docs.helloid.com/hc/en-us/articles/360014169933-How-to-Create-and-Manage-User-Defined-Variables)
<table>
  <tr><td><strong>Variable name</strong></td><td><strong>Example value</strong></td><td><strong>Description</strong></td></tr>
  <tr><td>NedapOnsConnectionUrl</td><td>https://api-staging.ons.io</td><td>Nedap Environment URL</td></tr>
  <tr><td>NedapOnsCertificatePassword</td><td>********</td><td>Nedap Certificate Password</td></tr>
  <tr><td>NedapOnsCertificatePFX</td><td>c:/folder/certificate.pfx</td><td>Full path of the Nedap certificate on the HelloID agent server</td></tr>
  <tr><td>NedapOnsLocationsMappingPath</td><td>c:/folder/oucode_locationid.csv</td><td>Full path of the Organisational Unit - Nedap Locations mapping file</td></tr>
  <tr><td>AfasBaseUri</td><td>https://<environmentcode>.rest.afas.online/profitrestservices</td><td>AFAS Environment URL</td></tr>
  <tr><td>AfasToken</td><td>********</td><td>AFAS Environment Tokencode</td></tr>
</table>

## Manual resources
This Delegated Form uses the following resources in order to run

### Powershell data source '[powershell-datasource]_Nedap-ons-csv-nedap-location-rules-edit'
This Powershell data source retrieves the configured mapping rules from the configured mapping file with corresponding AFAS organisational units and Nedap ONS locations.

### PowerShell data source '[powershell-datasource]_Nedap-ons-csv-nedap-locations-location-rules-edit'
This Powershell data source retrieves the available Nedap ONS locations from the configured environment.

### PowerShell data source '[powershell-datasource]_Nedap-ons-csv-nedap-locations-location-rules-mapped'
This Powershell data source retrieves the mapped Nedap ONS locations the configured mapping file.

### Delegated form task '[task]_Nedap-ons-modify-locations-rule'
This delegated form task will modify the selected rule to the configured mapping file. Effectively it deletes the selected rule and adds a new rule.

## Getting help
If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/service-automation/559-helloid-sa-nedap-modify-clientrange-mapping)

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
