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

of the possibility of such damages, arising out of the use of or inability to use the sample script, 

even if Microsoft has been advised of the possibility of such damages.
#>
Overview
AzureScriptsSamples is a collection of PowerShell scripts that can be used to manage and monitor Azure tenants, subscriptions, and resources. These scripts cover a wide range of common tasks in Azure administration, such as enforcing governance policies, gathering resource inventory, monitoring usage and costs, and automating Azure and Office 365 administration. The repository is organized into folders by category, with each folder grouping scripts by their purpose or the Azure service they target.
Below is a Table of Contents outlining each folder (category) in the repository, followed by detailed descriptions of each category and instructions for usage and contribution.
Table of Contents
AAD – Azure Active Directory scripts
AzureOpenAI – Azure OpenAI Service scripts
AzurePolicy – Azure Policy management scripts
Changes_Additions_removals – Change tracking scripts
Consumption – Azure consumption monitoring scripts
CostOptimization – Azure cost optimization scripts
Governance – Azure governance and compliance scripts
Inventory – Azure resource inventory scripts
Misc – Miscellaneous Azure scripts
Monitoring – Azure resource monitoring scripts
Network – Azure networking scripts
O365_M365 – Office 365/Microsoft 365 management scripts
OpenAI – OpenAI integration scripts
Quota – Azure service quotas checking scripts
Runbooks – Azure Automation runbooks
Sample output – Example output files from scripts
avd_mgmt – Azure Virtual Desktop management scripts
healthcheck – Azure health check scripts
workbook_json_extract – Azure Workbook data extraction scripts
Usage – How to use these scripts
Contributing – Guidelines for contributing to this repository
Folders and Categories
AAD
This folder contains scripts for managing Azure Active Directory (AAD). These scripts help automate directory tasks such as user and group management, role assignments, and retrieving directory information. For example, you might find scripts to export users and groups, manage AAD application registrations, or gather tenant details to streamline administrative duties.
AzureOpenAI
This folder contains scripts for interacting with the Azure OpenAI Service. The scripts in AzureOpenAI demonstrate how to configure and use Azure's OpenAI capabilities through PowerShell. Examples may include automating the deployment of OpenAI resources, calling the Azure OpenAI APIs to generate text or analysis, and integrating OpenAI models into automation workflows.
AzurePolicy
This folder contains scripts for managing Azure Policy. These scripts focus on Azure governance policies, including creating or updating policy definitions, assigning policies or initiatives to scopes (like subscriptions or resource groups), and retrieving compliance reports. For instance, scripts here can export non-compliant resources for given policies, update policy parameters programmatically, or bulk-assign tagging policies to multiple subscriptions. Use these to enforce standards and audit compliance across your Azure environment.
Changes_Additions_removals
This folder contains scripts and tools for tracking or documenting changes in the environment. They help identify when Azure resources or configurations have been added, modified, or removed. For example, a script might compare current resource states to a baseline and log differences, helping with change management and auditing. (This folder may also include notes or logs of updates to the repository scripts over time.)
Consumption
This folder contains scripts for monitoring Azure consumption and usage. The scripts gather data about Azure resource usage and consumption costs. For example, you might use these to pull daily or monthly usage details per subscription, list resource consumption by category (CPU, network, storage, etc.), or generate summaries of Azure spend. These scripts are useful for analyzing how resources are utilized over time and can help with internal chargeback or cost visibility.
CostOptimization
This folder contains scripts for optimizing Azure costs. They typically build on consumption data to identify cost-saving opportunities. For example, scripts may use Azure Advisor recommendations to find idle or underutilized resources (like VMs with low usage or unused IP addresses), retrieve cost data for a range of months, or export pricing information. You may find tools here to list all deallocated VMs (to identify waste), disable expensive services like unused Azure features, or aggregate cost information by resource owner. Use these scripts to reduce unnecessary spend and improve cost efficiency in Azure.
Governance
This folder contains scripts for managing Azure governance beyond just policies. These scripts ensure your Azure environment follows organizational standards. They might overlap with Azure Policy in some cases, but generally cover broader governance tasks such as tagging enforcement, naming conventions, subscription management, and compliance auditing. For example, you may find scripts to automatically tag resources in bulk with required metadata (owner, cost center, etc.), register resource providers across subscriptions, check for policy initiative compliance on resources, or audit role assignments and roles across subscriptions. These tools help maintain consistency and compliance in large Azure environments.
Inventory
This folder contains scripts for collecting and managing Azure inventory. In other words, these scripts enumerate resources across subscriptions and regions to provide an inventory or snapshot of your Azure environment. For example, there are scripts to list all VMs (and their properties) in all subscriptions, export resource group details to CSV, fetch subscription and tenant information (including subscription owners and Azure AD tenant IDs), and so on. These inventory scripts are useful for documentation, reporting, or as a prerequisite for other tasks (such as identifying resources that need tagging or checking compliance).
Misc
This folder contains miscellaneous scripts that do not fit neatly into the other categories. These scripts address various Azure-related tasks or utilities. For instance, you might find helper scripts to clear caches, test connectivity to Azure services, or one-off automation tasks requested by users. It's essentially a grab-bag of useful PowerShell scripts for Azure that are standalone in purpose.
Monitoring
This folder contains scripts for monitoring Azure resources. They help track the health, status, and performance of Azure services. For example, scripts might retrieve virtual machine uptime across all VMs, check for Azure Security Center/Defender alerts, or gather metrics (CPU, memory, network usage) for resources over time. Some scripts may integrate with Azure Monitor or log analytics to query logs and alerts. Use these to proactively monitor your environment or to generate health check reports on demand.
Network
This folder contains scripts for managing and monitoring Azure networking components. These scripts can automate tasks related to virtual networks, subnets, network security groups (NSGs), firewalls, and so on. Possible examples include scripts to list and audit NSG rules across subscriptions, gather on-premises VPN connection statuses, or configure network settings in bulk. They help ensure your Azure network infrastructure is configured correctly and can assist in security reviews of network access.
O365_M365
This folder contains scripts for managing Office 365 and Microsoft 365 resources via PowerShell. Even though these services are not Azure resources per se, Azure AD often ties in with M365 management. These scripts might cover tasks like reporting on Office 365 usage (Exchange, Teams, SharePoint), licensing users, or checking Microsoft 365 service health. They enable cloud administrators to automate Microsoft 365 operations and integrate those processes with Azure management routines.
OpenAI
This folder contains scripts related to OpenAI integration (outside of or in addition to Azure's OpenAI service). These could be early experiments or generic OpenAI API usage scripts. For example, you might find a script demonstrating how to call the OpenAI API (such as GPT-3/4) directly with an API key, or tools that integrate AI capabilities into PowerShell workflows. (Note: There is some overlap with the AzureOpenAI folder; the OpenAI folder might contain older or more general AI scripts that aren't specific to the Azure-provided service.)
Quota
This folder contains scripts for checking Azure quotas and usage limits. Azure services have limits (quotas) on resources (for example, how many cores, storage accounts, or IP addresses you can allocate per region or subscription). The Quota scripts help you query those limits and your current usage. For instance, a script might show how close you are to the VM cores quota in each region, or automatically create a support ticket/request to increase a quota if a threshold is reached. Use these tools to avoid hitting resource caps and to plan capacity ahead of time.
Runbooks
This folder contains scripts designed as Azure Automation Runbooks or samples that can be used in Azure Automation. These are typically geared for automated, scheduled tasks in Azure. The scripts might include the necessary modules or be written in a way that fits the runbook execution environment. Examples could include automatically shutting down VMs on a schedule to save costs, cleaning up unused snapshots periodically, or regularly sending a summary email of Azure usage. If you're using Azure Automation or plan to, the scripts here can be imported as runbooks to jump-start your automation workflows.
Sample output
This folder contains sample output files generated by some of the scripts in this repository. These samples show what the result of running a script might look like (for example, an HTML report of a health check, a CSV of inventory data, or JSON output from an Azure query). They are provided as references so you can understand the expected format of script outputs and verify that your environment produces similar results. You do not need to run these files; they are examples for documentation purposes.
avd_mgmt
This folder contains scripts for Azure Virtual Desktop (AVD) management. Azure Virtual Desktop is a service for virtualizing desktops and apps in Azure. The scripts in avd_mgmt help automate common AVD tasks, such as managing host pools, session hosts, user sessions, and scaling settings. For example, there might be scripts to add or remove session hosts in a host pool, retrieve session host health and usage, or schedule startup/shutdown of VMs in a host pool for cost optimization. These tools simplify administration of Azure Virtual Desktop deployments.
healthcheck
This folder contains scripts to perform health checks on Azure resources and environments. A health check script typically reviews a broad set of configurations and resource statuses to identify potential issues or to confirm that best practices are being followed. For instance, a health check script may verify that all critical VMs have backup enabled, or that no SQL databases are nearing storage capacity, and output an HTML or CSV report of the findings. Use these scripts to get an overall assessment of your Azure environment's health and compliance with operational standards.
workbook_json_extract
This folder contains scripts for extracting and processing data from Azure Monitor Workbooks. Azure Workbooks are interactive reports/dashboards often stored as JSON definitions. The scripts here can parse those JSON files to pull out useful information, such as queries, metrics, or parameters defined in a workbook. For example, a script might load a workbook JSON and output all the Kusto Queries inside it, or convert workbook charts into a CSV/HTML summary. This is useful for documentation or migration of workbook content, allowing you to analyze or repurpose queries and configuration from Azure Monitor Workbooks.
Usage
To use these scripts, simply clone or download the repository to your local machine (or open it in Azure Cloud Shell). Each script is standalone and can be run using PowerShell. You can execute a script by launching PowerShell, navigating to the script's directory, and running .\<script-name>.ps1.
Prerequisites: Ensure you have the necessary PowerShell modules installed and that you are authenticated to your Azure environment before running the scripts. We recommend installing the latest Az PowerShell module (or using Azure Cloud Shell, which has Az modules pre-installed). For many scripts, you'll need to run Connect-AzAccount to log in to Azure and select the appropriate subscription context. Office 365 related scripts may require the AzureAD or Microsoft Graph PowerShell modules, and any OpenAI scripts might require API keys or specific modules as noted in those scripts.
Running in Azure Cloud Shell: You can use Azure Cloud Shell in the Azure Portal to run these scripts without any local setup. Cloud Shell has most required modules installed and runs PowerShell in an Azure context. Just clone this repository in your Cloud Shell (git clone <repo URL>) and run the scripts as needed.
Script usage: Many scripts will prompt for input or have parameters you can specify. Read the top of each script – in many cases, there are comments explaining what the script does and how to use it. Some scripts may require you to edit a variable (like a subscription ID or resource name) within the file before running. Others might produce output files (for example, CSV or JSON reports) in a specified output folder or the current directory. Please refer to any README files within individual folders or the inline documentation at the top of each script for more detailed instructions or examples specific to that script.
⚠ Use caution when running scripts that make changes (like tagging resources or stopping VMs). It’s a good practice to test scripts in a non-production subscription or resource group first. Review the script code to understand the actions it will take. The provided scripts are meant to save time, but you are responsible for validating that they perform the desired actions in your environment.
Contributing
Contributions are welcome! If you have a script or improvement that you would like to add to this repository, please follow these guidelines:
Fork the repository and make your changes in a new branch of your fork. Organize any new scripts into the appropriate folder (or create a new folder if it truly doesn’t fit existing categories).
Documentation: Add comments at the top of your script explaining its purpose and usage. If the script is complex, consider updating the repository README (or a folder-specific README) with relevant details.
Testing: Try to test your script in your environment to ensure it runs without errors and achieves the intended results. (If applicable, sanitize any sample output or logs and consider adding to the Sample output folder for others to reference.)
When ready, open a Pull Request (PR) to this repository. In your PR description, clearly explain what the script does or what changes you have made, and why it would be useful to others.
We will review the PR. Ensure that your contribution does not include any sensitive information (like hardcoded credentials or subscription IDs) and that it aligns with the purpose of this collection.
By contributing, you agree that your submissions will be under the same license/Disclaimer (as outlined in the .NOTES section above). We appreciate your help in improving this collection of Azure scripts for the community!
Happy scripting! If you find this repository useful, feel free to star it on GitHub. If you encounter any issues or have suggestions, you can open an issue in the repository. Thank you for using AzureScriptsSamples.
