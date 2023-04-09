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

    Scriptname: get_azure_policy_states_export_to_storgeAccount.ps1
    Description:  Script to collect all Azure Policies assigned to scubscriptions 
                  results show Assignment subscription and compliance state
                  Script will generate report in   CSV to a storage account
          

    Purpose:  Audit of Assigned policies in a tenant

    Note: in order for process counter to show it must be in the first tab of PowerShell ISE

#> 


   Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings 'true'

 
 ######################33
 ##  Necessary Modules to be imported.

 import-module  Az.OperationalInsights -force

 import-module Az.PolicyInsights -Force 

 ############
 ## connect to Azure with authorized credentials 
 
 Connect-AzAccount -identity

 
#########################################

##  Get ist of subscriptions that will be read for discovery 
 
 



#########################################
##  uncomment this line if anomalies in queries display deprecation messages - This will allow script to continue discovery

##$ErrorActionPreference = 'silentlyContinue'

### get the list of subscriptions accessible by the credentials provided   

#########################################
### Clear Array collector 
## This is used to collect data using the custom schema in $resultobj
   $policystateresults = ''

#########################################

##  Get ist of subscriptions that will be read for discovery 
 
 $Subs =  Get-azSubscription | select Name, ID,TenantId


 foreach($Subscription in  $subs)
    {

            ## Progress counter 

                        $i = 0
              

                             $a = $a+1

                    # Determine the completion percentage
                    $SubCompleted = ($a/$subs.count) * 100
                    $Subactivity = "Subscriptions - Processing Iteration " + ($a + 1);
         
                         Write-Progress -Activity " $Subactivity " -Status "Progress:" -PercentComplete $SubCompleted

                    ###### end progrss counter for subscriptions

                             $SubscriptionName =  $Subscription.name

                             
                           $azcontext = (set-azcontext -SubscriptionName $SubscriptionName  -ErrorAction SilentlyContinue)

                       write-host "$SubscriptionName" -foregroundcolor yellow



  
               $policyStates =  Get-AzPolicyState   -All
          
  

          foreach($policystate in $policystates) 
          {
                #Get-AzPolicySetDefinition -SubscriptionId 


                 $policydefdata = Get-AzPolicyDefinition -Name $($policystate.PolicyDefinitionName)  -ErrorAction SilentlyContinue

################### counter for poilcy States
Get-AzPolicyEvent -PolicyDefinitionName $($policystate.PolicyDefinitionName)

            $i = $i+1
                    # Determine the completion percentage
                    $Completed = ($i/$policystates.count) * 100
                    $activity = "policystates- Processing Iteration " + ($i + 1);
         
                 Write-Progress -Activity " $activity " -Status "Progress:" -PercentComplete $Completed  


#################### end progress counter for policy states 


           
            $policystateobj = new-object PSObject 

              $policystateobj | Add-Member -MemberType NoteProperty -name   SubscriptionId    -value   $($policystate.SubscriptionId)
              $policystateobj | Add-Member -MemberType NoteProperty -name  ResourceType     -value      $($policystate.ResourceType)
              $policystateobj | Add-Member -MemberType NoteProperty -name  ResourceTags     -value      $($policystate.ResourceTags)   
              $policystateobj | Add-Member -MemberType NoteProperty -name  ResourceLocation     -value    $($policystate.ResourceLocation)
              $policystateobj | Add-Member -MemberType NoteProperty -name  IsCompliant     -value   $($policystate.IsCompliant)
              $policystateobj | Add-Member -MemberType NoteProperty -name  ComplianceState     -value   $($policystate.ComplianceState)
              $policystateobj | Add-Member -MemberType NoteProperty -name  EffectiveParameters     -value   $($policystate.EffectiveParameters)
              $policystateobj | Add-Member -MemberType NoteProperty -name  ResourceId     -value      $($policystate.ResourceId)
              $policystateobj | Add-Member -MemberType NoteProperty -name  ResourceGroup     -value   $($policystate.ResourceGroup)
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicySetDefinitionVersion     -value     $($policystate.PolicySetDefinitionVersion)
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicySetDefinitionParameters     -value     $($policystate.PolicySetDefinitionParameters) 
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicySetDefinitionOwner     -value   $($policystate.PolicySetDefinitionOwner)
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicySetDefinitionName     -value     $($policystate.PolicySetDefinitionName)
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicySetDefinitionId     -value       $($policystate.PolicySetDefinitionId)
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicySetDefinitionCategory     -value   $($policystate.PolicySetDefinitionCategory)
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicyEvaluationDetails     -value     $($policystate.PolicyEvaluationDetails)
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicyDefinitionVersion     -value     $($policystate.PolicyDefinitionVersion) 
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicyDefinitionReferenceId     -value   $($policystate.PolicyDefinitionReferenceId)
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicyDefinitionName     -value     $($policystate.PolicyDefinitionName)
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicyDefinitionId     -value       $($policystate.PolicyDefinitionId)
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicyDefinitionGroupNames     -value   $($policystate.PolicyDefinitionGroupNames)
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicyDefinitionCategory     -value     $($policystate.PolicyDefinitionCategory)
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicyDefinitionAction     -value      $($policystate.PolicyDefinitionAction)
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicyAssignmentVersion     -value   $($policystate.PolicyAssignmentVersion)
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicyAssignmentScope     -value     $($policystate.PolicyAssignmentScope)
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicyAssignmentParameters     -value    $($policystate.PolicyAssignmentParameters)  
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicyAssignmentOwner     -value   $($policystate.PolicyAssignmentOwner)
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicyAssignmentName     -value     $($policystate.PolicyAssignmentName)
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicyAssignmentId     -value     $($policystate.PolicyAssignmentId) 
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicyDescription     -value     $($policydefdata.properties.Description) 
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicyCategory     -value     $($policydefdata.properties.Metadata.Category) 
              $policystateobj | Add-Member -MemberType NoteProperty -name  PolicyDisplayName     -value     $($policydefdata.properties.DisplayName) 


              [array]$policystateresults += $policystateobj



              
           }   
  


    }



 $resultsfilename = "policystateresults.csv"

$policyStatusresults  | export-csv $resultsfilename  -NoTypeInformation   
  

 $policystateresults | sort-object SubscriptionId, ResourceGroup | Select SubscriptionId,`
ResourceGroup,`
ResourceType,`
ResourceTags,`
ResourceLocation,`
IsCompliant,`
ComplianceState,`
EffectiveParameters,`
ResourceId,`
PolicySetDefinitionVersion,`
PolicySetDefinitionParameters,`
PolicySetDefinitionOwner,`
PolicySetDefinitionName,`
PolicySetDefinitionId,`
PolicySetDefinitionCategory,`
PolicyEvaluationDetails,`
PolicyDefinitionVersion,`
PolicyDefinitionReferenceId,`
PolicyDefinitionName,`
PolicyDefinitionId,`
PolicyDefinitionGroupNames,`
PolicyDefinitionCategory,`
PolicyDefinitionAction,`
PolicyAssignmentVersion,`
PolicyAssignmentScope,`
PolicyAssignmentParameters,`
PolicyAssignmentOwner,`
PolicyAssignmentName,`
PolicyAssignmentId ,`
PolicyDescription ,`
PolicyCategory, `
PolicyDisplayName|`
   export-csv $resultsfilename  -NoTypeInformation   

  

##### storage subinfo

$Region = "<Location>"

 $subscriptionselected = '<Subscriptionname>'



$resourcegroupname = '<Resourcegroupname>'
$subscriptioninfo = get-azsubscription -SubscriptionName $subscriptionselected 
$TenantID = $subscriptioninfo | Select-Object tenantid
$storageaccountname = '<Storageaccountname>'
$storagecontainer = 'PolicyStates'
### end storagesub info

set-azcontext -Subscription $($subscriptioninfo.Name)  -Tenant $($TenantID.TenantId)


#BEGIN Create Storage Accounts
 
 
 
 try
 {
     if (!(Get-AzStorageAccount -ResourceGroupName $resourcegroupname -Name $storageaccountname ))
    {  
        Write-Host "Storage Account Does Not Exist, Creating Storage Account: $storageAccount Now"

        # b. Provision storage account
        New-AzStorageAccount -ResourceGroupName $resourcegroupname  -Name $storageaccountname -Location $region -AccessTier Hot -SkuName Standard_LRS -Kind BlobStorage -Tag @{"owner" = "Jerry wolff"; "purpose" = "Az Automation storage write" } -Verbose
 
     
        Get-AzStorageAccount -Name   $storageaccountname  -ResourceGroupName  $resourcegroupname  -verbose
     }
   }
   Catch
   {
         WRITE-DEBUG "Storage Account Aleady Exists, SKipping Creation of $storageAccount"
   
   } 
        $StorageKey = (Get-AzStorageAccountKey -ResourceGroupName $resourcegroupname  –StorageAccountName $storageaccountname).value | select -first 1
        $destContext = New-azStorageContext  –StorageAccountName $storageaccountname `
                                        -StorageAccountKey $StorageKey


             #Upload user.csv to storage account

        try
            {
                  if (!(get-azstoragecontainer -Name $storagecontainer -Context $destContext))
                     { 
                         New-azStorageContainer $storagecontainer -Context $destContext
                        }
             }
        catch
             {
                Write-Warning " $storagecontainer container already exists" 
             }
       

         Set-azStorageBlobContent -Container $storagecontainer -Blob $resultsfile  -File $resultsfilename -Context $destContext
        
 








 














