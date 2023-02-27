﻿<#
.NOTES

    THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 

    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 

    FITNESS FOR A PARTICULAR PURPOSE.

    This sample is not supported under any Microsoft standard support program or service. 

    The script is provided AS IS without warranty of any kind. Microsoft further disclaims all

    implied warranties including, without limitation, any implied warranties of merchantability

    or of fitness for a particular purpose. The entire risk arising out of the use or performance

    of the sample and documentation remains with you. In no event shall Microsoft, its authors,

    or anyone else involved in the creation, production, or delivery of the script be liable for 

    any damages whatsoever (including, without limitation, damages for loss of business profits, 

    business interruption, loss of business information, or other pecuniary loss) arising out of 

    the use of or inability to use the sample or documentation, even if Microsoft has been advised 

    of the possibility of such damages, rising out of the use of or inability to use the sample script, 

    even if Microsoft has been advised of the possibility of such damages.

    Script Name: update_policy_json_definition_parameters_and assign_to_scope.ps1
    Description: Custom script to update an Azure policy definitinon parameter Json file with a list of allowed values read from an csv input file 
                 stored in a storage account.  Script will read input list of allowed values , update JSON parameter file, Store updated file in a storage account and 
                 Remove current policy's scope assignment and re-assign with the newly updated list of values to the scope. 

#> 

####### Suppress powershell module changes warning during execution 

  Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings 'true'
   
#################  Connecto toe azure context based on login credentials 
#######  if connect-axaacount -Identity is used, the managed identity will be used for context in the execution 
#######  for Azure government tenant use  , run connect-azconnect -Environment AzureUSGovernment


connect-azaccount   # -identity 

import-module az.storage
import-module Az.Resources 


$subscriptionselected = 'Azure Subscription 1'



################  Set up storage account ################


$resourcegroupname = 'jwautomationrg'
$subscriptioninfo = get-azsubscription -SubscriptionName $subscriptionselected 
$TenantID = $subscriptioninfo | Select-Object tenantid
$storageaccountname = 'asnstoragesa'
$storagecontainer = 'policyupdates'
$templatecontainer = 'templatesscntr'

$region = 'westus'

### end storagesub info

Set-azcontext -Subscription $($subscriptioninfo.Name) -Tenant $subscriptioninfo.TenantId

 ####resourcegroup 
 try
 {
     if (!(Get-azresourcegroup -Location 'westus'  -erroraction "continue" ) )
    {  
        Write-Host "resourcegroup Does Not Exist, Creating resourcegroup  : $resourcegroupname Now"

        # b. Provision resourcegroup
        New-azresourcegroup -Name  $resourcegroupname -Location $region -Tag @{"owner" = "Jerry wolff"; "purpose" = "Az Automation" } -Verbose -Force
 
     
        Get-azresourcegroup    -ResourceGroupName  $resourcegroupname  -verbose
     }
   }
   Catch
   {
         WRITE-DEBUG "Resourcegroup   Aleady Exists, SKipping Creation of resourcegroupname"
   
   }

    
 try
 {
     if (!(Get-AzStorageAccount -ResourceGroupName $resourcegroupname -Name $storageaccountname  -erroraction "continue" ) )
    {  
        Write-Host "Storage Account Does Not Exist, Creating Storage Account: $storageAccount Now"

        # b. Provision storage account
        New-AzStorageAccount  -ResourceGroupName $resourcegroupname  -Name $storageaccountname -Location $region -AccessTier Hot -SkuName Standard_LRS -Kind BlobStorage -Tag @{"owner" = "Jerry wolff"; "purpose" = "Az Automation storage write" } -Verbose 
 
        start-sleep 30

        Get-AzStorageAccount -Name   $storageaccountname  -ResourceGroupName  $resourcegroupname  -verbose
     }
   }
   Catch
   {
         WRITE-DEBUG "Storage Account Aleady Exists, SKipping Creation of $storageAccount"
   
   } 
 
             #Upload user.json to storage account

        try
            {
                  if (!(get-azstoragecontainer -Name $storagecontainer -Context $destContext))
                     { 
                         New-azStorageContainer $storagecontainer -Context $destContext

                         
                        start-sleep 30

                        }
             }
        catch
             {
                Write-Warning " $storagecontainer container already exists" 
             }
       

    #############################################################

     


set-azcontext -Subscription $($subscriptioninfo.Name)  -Tenant $($TenantID.TenantId)



$StorageKey = (Get-AzStorageAccountKey -ResourceGroupName $resourcegroupname  –StorageAccountName $storageaccountname).value | select -first 1
$destContext = New-azStorageContext  –StorageAccountName $storageaccountname `
                 -StorageAccountKey $StorageKey

########## Get Policy template 



$Policyjsontemplate = "asntaggingdefinition.json"

$jsondefinitionblob = get-AzStorageBlob -Blob $Policyjsontemplate -Container $templatecontainer -Context $destContext

 
 [array]$policytemplatejsoncontent = Get-AzStorageBlobContent -Blob $Policyjsontemplate -Container $templatecontainer    -Context $destContext -Force


$policydefinition = get-Content -Raw  $($policytemplatejsoncontent.name)
$policydefinition



###### get parameters



$Policyjsonparamsfile = "asntaggingdefinition.parameters.json"

$jsonparamsblob = get-AzStorageBlob -Blob $Policyjsonparamsfile -Container $templatecontainer -Context $destContext 

 
[array]$policyjsonparamscontent = Get-AzStorageBlobContent -Blob $Policyjsonparamsfile -Container $templatecontainer   -Context $destContext -Force

 $policyparameters = get-Content -raw $($policyjsonparamscontent.name)
$policyparameters



 ###### Get asn codes files from storage container 

 $sourcecontainer = 'sourceasn'
 $asnsourceblob = 'cmdb_ci_service_discovered.csv'

 $asncodescontainer =  get-AzStorageBlob -Blob $asnsourceblob -Container $sourcecontainer -Context $destContext 
 
 $asvcodesfilecontent = Get-AzStorageBlobContent -Blob $asnsourceblob -Container $sourcecontainer   -Context $destContext -force

 $asncodes = import-csv  $asvcodesfilecontent.Name


#Read local file and get JSON object
  
  
 #######  Set value updates 


        #Convert JSON file to an object  
        $JsonParameters = ConvertFrom-Json -InputObject $policyparameters

         foreach($asncode in $asncodes)
         {

            $JsonParameters.listofallowedtagValues.allowedValues += "$($asncode.'Application Service Number')"

         } 
 

    ############  Create blob file for archive and audit

         $updatedpolicy = "updatedpolicy.json"
         $JsonParameters | ConvertTo-Json -Depth 10  | out-file  $updatedpolicy

    ################################## Add raw content to Variable

        $updated_policy = $JsonParameters | ConvertTo-Json -Depth 10   

  
          #Get-Content -Raw   $updatedpolicy
    ##################  Write updated parameters file to Storage account 

          Set-azStorageBlobContent -Container $storagecontainer -Blob $updatedpolicy  -File $updatedpolicy  -Context $destContext -Force


    ############## Apply updates to Policy parameters and reapply to Definition

          New-AzPolicyDefinition -Name asntaggingdefinition -DisplayName 'asntaggingdefinition' -Policy $policydefinition -Parameter $($updated_policy) -Verbose

       $policytoassign = Get-AzPolicyDefinition -Name asntaggingdefinition 

       
        
          Get-AzPolicyDefinition -Name asntaggingdefinition -SubscriptionId $subscriptioninfo.Id  | `

         Set-AzPolicyDefinition      -Parameter $($updated_policy) -DisplayName asntaggingdefinition -name asntaggingdefinition


  ############## Test/ Validation Policy and values 


  $policydefinitionproperties = Get-AzPolicyDefinition -Name asntaggingdefinition -SubscriptionId $subscriptioninfo.Id | select-object -ExpandProperty properties
   
  $policydefinitionproperties

   
  write-host "$($policydefinitionproperties.parameters.tagName.metadata.description) " -ForegroundColor Green
  write-host "$($policydefinitionproperties.parameters.tagName.metadata.displayName) " -ForegroundColor Green


 $($policydefinitionproperties.parameters).listofallowedtagValues.allowedValues




#####################################  Reassign subscription to update policy
######### Remove old assignment on resource
 
$PolicyAssignment = Get-AzPolicyAssignment  -PolicyDefinitionId $policytoassign.PolicyDefinitionId
Remove-AzPolicyAssignment -Id $PolicyAssignment.ResourceId  

 
 ##################  Reassign Policydefinition
 
 $listofallowedtagValues  = @{'tagName'='AppServiceName'; 'listofallowedtagValues'=$($JsonParameters.listofallowedtagValues.allowedValues) }

 $assigntoscope =   New-AzPolicyAssignment -Name 'asntaggingdefinitionasg' -PolicyDefinition  $policytoassign  -PolicyParameterObject  $listofallowedtagValues  -Scope  "/subscriptions/$($subscriptioninfo.Id)" -NonComplianceMessage @{Message="Stop making mistakes - I will find you"}
        
 



