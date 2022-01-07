[comment]: # "Auto-generated SOAR connector documentation"
# DeepSight

Publisher: Splunk  
Connector Version: 1\.0\.1  
Product Vendor: Accenture  
Product Name: DeepSight  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.9\.39220  

This app supports hunting and a variety of investigative actions, in addition to report ingestion, from the Accenture DeepSight Intelligence cyber security service

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a DeepSight asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api\_key** |  required  | password | API key
**max\_reports\_first\_ingestion** |  optional  | numeric | Maximum latest reports to poll first time
**download\_report** |  optional  | boolean | Download report to vault if available

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[on poll](#action-on-poll) - Ingest reports  
[domain reputation](#action-domain-reputation) - Get domain reputation  
[file reputation](#action-file-reputation) - Get file reputation  
[url reputation](#action-url-reputation) - Get URL reputation  
[ip reputation](#action-ip-reputation) - Get IP reputation  
[hunt file](#action-hunt-file) - Look for information about a file  
[get report](#action-get-report) - Get report details  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'on poll'
Ingest reports

Type: **ingest**  
Read only: **True**

<p>For the first poll, ingests the latest number of reports set in <b>max\_reports\_first\_ingestion</b>\. Subsequent polls ingest new reports\. To ingest all current reports, set <b>max\_reports\_first\_ingestion</b> to a number equal to or greater than the number of reports in DeepSight and set the poll interval large enough to allow all reports to be ingested\. The poll interval can be adjusted after the first poll completes\.<p><table><tbody><tr class='plain'><th>IOC</th><th>Artifact Name</th><th>CEF Field</th></tr><tr><td>Address IPv4</td><td>IP Artifact</td><td>deviceAddress</td></tr><tr><td>Email</td><td>Email Address Artifact</td><td>emailAddress</td></tr><tr><td>File</td><td>File Artifact</td><td>fileHashMd5, fileHashSha256, fileName, fileSize</td></tr><tr><td>Host</td><td>Domain Artifact</td><td>deviceHostName</td></tr><tr><td>URL</td><td>URL Artifact</td><td>requestURL</td></tr><td>ReportID</td><td>Report Artifact</td><td>deepsightReportId</td><tr></tr></tbody></table>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container\_id** |  optional  | Comma separated report IDs | string | 
**start\_time** |  optional  | Parameter ignored in this app | numeric | 
**artifact\_count** |  optional  | Parameter ignored in this app | numeric | 
**end\_time** |  optional  | Parameter ignored in this app | numeric | 
**container\_count** |  optional  | Maximum number of reports to ingest | numeric | 

#### Action Output
No Output  

## action: 'domain reputation'
Get domain reputation

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `url`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.schemaVersion | numeric | 
action\_result\.data\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.whitelisted | boolean | 
action\_result\.data\.\*\.firstSeen | string | 
action\_result\.data\.\*\.lastSeen | string | 
action\_result\.data\.\*\.reputationValues\.reputation | numeric | 
action\_result\.data\.\*\.reputationValues\.confidence | numeric | 
action\_result\.data\.\*\.reputationValues\.hostility | numeric | 
action\_result\.data\.\*\.matiReports\.\*\.id | numeric |  `deepsight report id` 
action\_result\.data\.\*\.matiReports\.\*\.title | string | 
action\_result\.data\.\*\.matiReports\.\*\.date | string | 
action\_result\.data\.\*\.matiReports\.\*\.uri | string | 
action\_result\.data\.\*\.whois\.person | string | 
action\_result\.data\.\*\.whois\.email | string |  `email` 
action\_result\.data\.\*\.whois\.organization | string | 
action\_result\.data\.\*\.whois\.city | string | 
action\_result\.data\.\*\.whois\.postalCode | string | 
action\_result\.data\.\*\.whois\.country | string | 
action\_result\.data\.\*\.whois\.created | string | 
action\_result\.data\.\*\.whois\.updated | string | 
action\_result\.data\.\*\.whois\.expires | string | 
action\_result\.data\.\*\.whois\.registrar | string | 
action\_result\.data\.\*\.whois\.nameServers | string |  `domain` 
action\_result\.data\.\*\.ips\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.ips\.\*\.uri | string | 
action\_result\.data\.\*\.urls\.\*\.url | string |  `url` 
action\_result\.data\.\*\.urls\.\*\.uri | string | 
action\_result\.data\.\*\.behaviours\.\*\.type | string | 
action\_result\.data\.\*\.behaviours\.\*\.behaviour | string | 
action\_result\.data\.\*\.behaviours\.\*\.description | string | 
action\_result\.data\.\*\.targetCountries | string | 
action\_result\.data\.\*\.targetIndustries\.\*\.naics | numeric | 
action\_result\.data\.\*\.targetIndustries\.\*\.name | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.domain | string |  `url`  `domain` 
action\_result\.summary\.reputation | numeric | 
action\_result\.summary\.confidence | numeric | 
action\_result\.summary\.hostility | numeric | 
action\_result\.summary\.whitelisted | boolean | 
action\_result\.summary\.last\_seen | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'file reputation'
Get file reputation

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file** |  required  | File hash \(MD5 or SHA256\) | string |  `hash`  `md5`  `sha256` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.schemaVersion | numeric | 
action\_result\.data\.\*\.MD5 | string |  `md5` 
action\_result\.data\.\*\.SHA256 | string |  `sha256` 
action\_result\.data\.\*\.reputation | string | 
action\_result\.data\.\*\.matiReports\.\*\.id | numeric |  `deepsight report id` 
action\_result\.data\.\*\.matiReports\.\*\.title | string | 
action\_result\.data\.\*\.matiReports\.\*\.date | string | 
action\_result\.data\.\*\.matiReports\.\*\.uri | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.file | string |  `hash`  `md5`  `sha256` 
action\_result\.summary\.reputation | string | 
action\_result\.summary\.total\_reports | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'url reputation'
Get URL reputation

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to query | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.schemaVersion | numeric | 
action\_result\.data\.\*\.url | string |  `url`  `file name` 
action\_result\.data\.\*\.whitelisted | boolean | 
action\_result\.data\.\*\.firstSeen | string | 
action\_result\.data\.\*\.lastSeen | string | 
action\_result\.data\.\*\.host\.domain | string |  `domain` 
action\_result\.data\.\*\.host\.uri | string | 
action\_result\.data\.\*\.matiReports\.\*\.id | numeric |  `deepsight report id` 
action\_result\.data\.\*\.matiReports\.\*\.title | string | 
action\_result\.data\.\*\.matiReports\.\*\.date | string | 
action\_result\.data\.\*\.matiReports\.\*\.uri | string | 
action\_result\.data\.\*\.whois\.person | string | 
action\_result\.data\.\*\.whois\.email | string |  `email` 
action\_result\.data\.\*\.whois\.organization | string | 
action\_result\.data\.\*\.whois\.city | string | 
action\_result\.data\.\*\.whois\.postalCode | string | 
action\_result\.data\.\*\.whois\.country | string | 
action\_result\.data\.\*\.whois\.created | string | 
action\_result\.data\.\*\.whois\.updated | string | 
action\_result\.data\.\*\.whois\.expires | string | 
action\_result\.data\.\*\.whois\.registrar | string | 
action\_result\.data\.\*\.whois\.nameServers | string |  `domain` 
action\_result\.data\.\*\.behaviours\.\*\.behaviour | string | 
action\_result\.data\.\*\.behaviours\.\*\.type | string | 
action\_result\.data\.\*\.behaviours\.\*\.description | string | 
action\_result\.data\.\*\.ips\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.ips\.\*\.uri | string | 
action\_result\.data\.\*\.targetCountries | string | 
action\_result\.data\.\*\.targetIndustries\.\*\.naics | numeric | 
action\_result\.data\.\*\.targetIndustries\.\*\.name | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.summary\.whitelisted | boolean | 
action\_result\.summary\.last\_seen | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'ip reputation'
Get IP reputation

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.schemaVersion | numeric | 
action\_result\.data\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.whitelisted | boolean | 
action\_result\.data\.\*\.firstSeen | string | 
action\_result\.data\.\*\.lastSeen | string | 
action\_result\.data\.\*\.reputationValues\.reputation | numeric | 
action\_result\.data\.\*\.reputationValues\.confidence | numeric | 
action\_result\.data\.\*\.reputationValues\.hostility | numeric | 
action\_result\.data\.\*\.matiReports\.\*\.id | numeric |  `deepsight report id` 
action\_result\.data\.\*\.matiReports\.\*\.title | string | 
action\_result\.data\.\*\.matiReports\.\*\.date | string | 
action\_result\.data\.\*\.matiReports\.\*\.uri | string | 
action\_result\.data\.\*\.organization\.name | string | 
action\_result\.data\.\*\.organization\.type | string | 
action\_result\.data\.\*\.organization\.naics | numeric | 
action\_result\.data\.\*\.organization\.isic | string | 
action\_result\.data\.\*\.network\.carrier | string | 
action\_result\.data\.\*\.network\.asn | numeric | 
action\_result\.data\.\*\.network\.lineSpeed | string | 
action\_result\.data\.\*\.network\.ipRouting | string | 
action\_result\.data\.\*\.network\.anonymizerStatus | string | 
action\_result\.data\.\*\.network\.proxyType | string | 
action\_result\.data\.\*\.network\.proxyLevel | string | 
action\_result\.data\.\*\.network\.proxyLastDetected | string | 
action\_result\.data\.\*\.geolocation\.country | string | 
action\_result\.data\.\*\.geolocation\.city | string | 
action\_result\.data\.\*\.geolocation\.latitude | numeric | 
action\_result\.data\.\*\.geolocation\.longitude | numeric | 
action\_result\.data\.\*\.behaviours\.\*\.behaviour | string | 
action\_result\.data\.\*\.behaviours\.\*\.type | string | 
action\_result\.data\.\*\.behaviours\.\*\.description | string | 
action\_result\.data\.\*\.domains\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.domains\.\*\.uri | string | 
action\_result\.data\.\*\.urls\.\*\.url | string |  `url` 
action\_result\.data\.\*\.urls\.\*\.uri | string | 
action\_result\.data\.\*\.targetCountries | string | 
action\_result\.data\.\*\.targetIndustries\.\*\.naics | numeric | 
action\_result\.data\.\*\.targetIndustries\.\*\.name | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.summary\.reputation | numeric | 
action\_result\.summary\.confidence | numeric | 
action\_result\.summary\.hostility | numeric | 
action\_result\.summary\.whitelisted | boolean | 
action\_result\.summary\.last\_seen | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'hunt file'
Look for information about a file

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file** |  required  | File hash to hunt | string |  `hash`  `md5`  `sha256` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.id | numeric |  `deepsight report id` 
action\_result\.data\.\*\.date | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.uri | string | 
action\_result\.data\.\*\.report\_data\.schemaVersion | numeric | 
action\_result\.data\.\*\.report\_data\.threatDomains | string | 
action\_result\.data\.\*\.report\_data\.yaraSignature\.\*\.name | string | 
action\_result\.data\.\*\.report\_data\.yaraSignature\.\*\.status | string | 
action\_result\.data\.\*\.report\_data\.snortSignature\.\*\.name | string | 
action\_result\.data\.\*\.report\_data\.snortSignature\.\*\.status | string | 
action\_result\.data\.\*\.report\_data\.adversaries\.\*\.name | string | 
action\_result\.data\.\*\.report\_data\.adversaries\.\*\.uri | string | 
action\_result\.data\.\*\.report\_data\.adversaries\.\*\.type | string | 
action\_result\.data\.\*\.report\_data\.ips\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.report\_data\.ips\.\*\.classifications | string | 
action\_result\.data\.\*\.report\_data\.ips\.\*\.relatedDomains | string |  `domain` 
action\_result\.data\.\*\.report\_data\.ips\.\*\.relatedUrls | string |  `url` 
action\_result\.data\.\*\.report\_data\.ips\.\*\.uri | string | 
action\_result\.data\.\*\.report\_data\.domains\.\*\.uri | string | 
action\_result\.data\.\*\.report\_data\.domains\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.report\_data\.domains\.\*\.classifications | string | 
action\_result\.data\.\*\.report\_data\.domains\.\*\.relatedIps | string |  `ip` 
action\_result\.data\.\*\.report\_data\.domains\.\*\.relatedUrls | string |  `url` 
action\_result\.data\.\*\.report\_data\.emails\.\*\.subject | string | 
action\_result\.data\.\*\.report\_data\.emails\.\*\.from | string |  `email` 
action\_result\.data\.\*\.report\_data\.emails\.\*\.date | string | 
action\_result\.data\.\*\.report\_data\.emails\.\*\.content | string | 
action\_result\.data\.\*\.report\_data\.emails\.\*\.relatedFileHashes | string | 
action\_result\.data\.\*\.report\_data\.emails\.\*\.relatedUrls | string |  `url` 
action\_result\.data\.\*\.report\_data\.files\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.report\_data\.files\.\*\.uri | string | 
action\_result\.data\.\*\.report\_data\.files\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.report\_data\.files\.\*\.isMalicious | boolean | 
action\_result\.data\.\*\.report\_data\.files\.\*\.detectionName | string | 
action\_result\.data\.\*\.report\_data\.files\.\*\.filename | string |  `file name` 
action\_result\.data\.\*\.report\_data\.files\.\*\.size | string | 
action\_result\.data\.\*\.report\_data\.files\.\*\.parentMd5s | string |  `md5` 
action\_result\.data\.\*\.report\_data\.files\.\*\.childMd5s | string |  `md5` 
action\_result\.data\.\*\.report\_data\.files\.\*\.exploitedVulnerabilities\.\*\.cve | string | 
action\_result\.data\.\*\.report\_data\.files\.\*\.exploitedVulnerabilities\.\*\.bid | string | 
action\_result\.data\.\*\.report\_data\.files\.\*\.exploitedVulnerabilities\.\*\.url | string |  `url` 
action\_result\.data\.\*\.report\_data\.files\.\*\.relatedIps | string |  `ip` 
action\_result\.data\.\*\.report\_data\.files\.\*\.relatedDomains | string |  `domain` 
action\_result\.data\.\*\.report\_data\.files\.\*\.relatedUrls | string |  `url` 
action\_result\.data\.\*\.report\_data\.campaigns\.\*\.name | string | 
action\_result\.data\.\*\.report\_data\.campaigns\.\*\.status | string | 
action\_result\.data\.\*\.report\_data\.sources\.regions\.\*\.regionName | string | 
action\_result\.data\.\*\.report\_data\.sources\.regions\.\*\.subregions\.\*\.countries\.\*\.iso | string | 
action\_result\.data\.\*\.report\_data\.sources\.regions\.\*\.subregions\.\*\.countries\.\*\.name | string | 
action\_result\.data\.\*\.report\_data\.sources\.regions\.\*\.subregions\.\*\.subregionName | string | 
action\_result\.data\.\*\.report\_data\.targets\.regions\.\*\.regionName | string | 
action\_result\.data\.\*\.report\_data\.targets\.regions\.\*\.subregions\.\*\.countries\.\*\.iso | string | 
action\_result\.data\.\*\.report\_data\.targets\.regions\.\*\.subregions\.\*\.countries\.\*\.name | string | 
action\_result\.data\.\*\.report\_data\.targets\.regions\.\*\.subregions\.\*\.subregionName | string | 
action\_result\.data\.\*\.report\_data\.targets\.industries\.\*\.name | string | 
action\_result\.data\.\*\.report\_data\.targets\.industries\.\*\.naics | numeric | 
action\_result\.data\.\*\.report\_data\.targets\.industries\.\*\.percentage | numeric | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.file | string |  `hash`  `md5`  `sha256` 
action\_result\.summary\.total\_reports | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get report'
Get report details

Type: **investigate**  
Read only: **True**

It has been noticed that report availability from API might lag the Accenture DeepSight database\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**mati\_id** |  required  | Report ID to query | string |  `deepsight report id` 
**download\_report** |  optional  | Download PDF report to vault if available | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.schemaVersion | numeric | 
action\_result\.data\.\*\.threatDomains | string | 
action\_result\.data\.\*\.yaraSignature\.\*\.name | string | 
action\_result\.data\.\*\.yaraSignature\.\*\.signature | string | 
action\_result\.data\.\*\.snortSignature\.\*\.name | string | 
action\_result\.data\.\*\.snortSignature\.\*\.signature | string | 
action\_result\.data\.\*\.adversaries\.\*\.name | string | 
action\_result\.data\.\*\.adversaries\.\*\.uri | string | 
action\_result\.data\.\*\.adversaries\.\*\.type | string | 
action\_result\.data\.\*\.ips\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.ips\.\*\.uri | string | 
action\_result\.data\.\*\.ips\.\*\.classifications | string | 
action\_result\.data\.\*\.ips\.\*\.relatedDomains | string |  `domain` 
action\_result\.data\.\*\.ips\.\*\.relatedUrls | string |  `url` 
action\_result\.data\.\*\.domains\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.domains\.\*\.uri | string | 
action\_result\.data\.\*\.domains\.\*\.classifications | string | 
action\_result\.data\.\*\.domains\.\*\.relatedIps | string |  `ip` 
action\_result\.data\.\*\.domains\.\*\.relatedUrls | string |  `url` 
action\_result\.data\.\*\.emails\.\*\.subject | string | 
action\_result\.data\.\*\.emails\.\*\.from | string |  `email` 
action\_result\.data\.\*\.emails\.\*\.date | string | 
action\_result\.data\.\*\.emails\.\*\.content | string | 
action\_result\.data\.\*\.emails\.\*\.relatedFileHashes | string |  `md5` 
action\_result\.data\.\*\.emails\.\*\.relatedUrls | string |  `url` 
action\_result\.data\.\*\.files\.\*\.filename | string |  `file name` 
action\_result\.data\.\*\.files\.\*\.size | string | 
action\_result\.data\.\*\.files\.\*\.isMalicious | boolean | 
action\_result\.data\.\*\.files\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.files\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.files\.\*\.uri | string | 
action\_result\.data\.\*\.files\.\*\.detectionName | string | 
action\_result\.data\.\*\.files\.\*\.parentMd5s | string |  `md5` 
action\_result\.data\.\*\.files\.\*\.childMd5s | string |  `md5` 
action\_result\.data\.\*\.files\.\*\.exploitedVulnerabilities\.\*\.cve | string | 
action\_result\.data\.\*\.files\.\*\.exploitedVulnerabilities\.\*\.bid | string | 
action\_result\.data\.\*\.files\.\*\.exploitedVulnerabilities\.\*\.url | string |  `url` 
action\_result\.data\.\*\.files\.\*\.relatedIps | string |  `ip` 
action\_result\.data\.\*\.files\.\*\.relatedDomains | string |  `domain` 
action\_result\.data\.\*\.files\.\*\.relatedUrls | string |  `url` 
action\_result\.data\.\*\.campaigns\.\*\.name | string | 
action\_result\.data\.\*\.campaigns\.\*\.status | string | 
action\_result\.data\.\*\.sources\.regions\.\*\.regionName | string | 
action\_result\.data\.\*\.sources\.regions\.\*\.subregions\.\*\.subregionName | string | 
action\_result\.data\.\*\.sources\.regions\.\*\.subregions\.\*\.countries\.\*\.name | string | 
action\_result\.data\.\*\.sources\.regions\.\*\.subregions\.\*\.countries\.\*\.iso | string | 
action\_result\.data\.\*\.targets\.industries\.\*\.naics | numeric | 
action\_result\.data\.\*\.targets\.industries\.\*\.name | string | 
action\_result\.data\.\*\.targets\.industries\.\*\.percentage | numeric | 
action\_result\.data\.\*\.targets\.regions\.\*\.regionName | string | 
action\_result\.data\.\*\.targets\.regions\.\*\.subregions\.\*\.subregionName | string | 
action\_result\.data\.\*\.targets\.regions\.\*\.subregions\.\*\.countries\.\*\.name | string | 
action\_result\.data\.\*\.targets\.regions\.\*\.subregions\.\*\.countries\.\*\.iso | string | 
action\_result\.data\.\*\.report\_summary\_data\.id | string |  `deepsight report id` 
action\_result\.data\.\*\.report\_summary\_data\.uri | string | 
action\_result\.data\.\*\.report\_summary\_data\.date | string | 
action\_result\.data\.\*\.report\_summary\_data\.title | string | 
action\_result\.data\.\*\.report\_summary\_data\.summary | string | 
action\_result\.data\.\*\.vault\.size | numeric | 
action\_result\.data\.\*\.vault\.type | string | 
action\_result\.data\.\*\.vault\.action | string | 
action\_result\.data\.\*\.vault\.contains | string | 
action\_result\.data\.\*\.vault\.vault\_id | string |  `vault id` 
action\_result\.data\.\*\.vault\.app\_run\_id | numeric | 
action\_result\.data\.\*\.vault\.report\_file\_name | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.mati\_id | string |  `deepsight report id` 
action\_result\.parameter\.download\_report | boolean | 
action\_result\.summary\.summary\_title | string | 
action\_result\.summary\.vault\_id | string |  `vault id` 
action\_result\.summary\.pdf\_availability | boolean | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 