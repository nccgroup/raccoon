# Raccoon: Salesforce object access auditor

Released as open source by NCC Group Plc - https://www.nccgroup.com/

Developed by Jerome Smith [@exploresecurity](https://twitter.com/exploresecurity) (with thanks to Viktor Gazdag [@wucpi](https://twitter.com/wucpi))

https://www.github.com/nccgroup/raccoon

Released under AGPL - refer to `LICENSE` for more information.

## Description

This tool establishes which Profiles and Permissions Sets (with active users) have some combination of read/edit/delete permissions to ALL records for a given set of objects, based on their effective sharing and objects settings. From this output, misconfigurations that potentially allow excessive access to objects that hold sensitive data can be investigated. Refer to the accompanying blog post for background at https://research.nccgroup.com/2021/06/28/are-you-oversharing-in-salesforce.

It is recommended that results are verified manually with direct reference to the Salesforce configuration and/or testing of the affected Profiles and Permission Sets. Should discrepancies be found, please [file an issue](#reporting-bugs) with as much detail as possible.

## Usage

Requirements:

* Python 3
* The Python `requests` module (covered by `requirements.txt`)
* An account with the following minimum permissions:
	* 'API Enabled'
	* 'View Setup and Configuration'
	* 'Modify Metadata Through Metadata API Functions' (see note on ['Account permissions'](#account-permissions))
	* Read permission on all the objects to be audited (or grant 'View All Data')
* For authentication, supply EITHER `username` + `password` + (optional) `token` OR `sessionId` (more details in the [Authentication](#authentication) section).

Create a JSON config file (or use `config.json` as a template) and populate as required:

```
{
	"hostname": "somewhere.my.salesforce.com",
	"username": "",
	"password": "",
	"token": "<optional token>",
	"sessionId": "",
	"objects": ["Account", "Contact"],
	"checkLimits": true,
	"debug": <optional debug level (0, 1 or 2)>
}
```

`objects` is a list of Salesforce objects of interest (i.e. the data you care about most). Using the formal API names is the most reliable method but, should a match not be found, Raccoon will try some simple matches based, for example, on the display label. If Raccoon still fails to find a match, the program will carry on but flag this up in the output.

`checkLimits` allows you to check the allowance of API calls remaining for the instance under investigation within the 24-hour rolling period. Raccoon makes relatively few calls per object (in addition to a fixed number per run) but, as a courtesy, this parameter allows you to check your limits before proceeding. The default value is `true`. The total number of possible remaining requests at the checkpoint is not certain because the number of calls will depend on how many objects have a 'Controlled by Parent' sharing model. The stated number assumes that they all do and is thus a maximum.

Run:

```
git clone https://github.com/nccgroup/raccoon
pip3 install -r requirements.txt
python3 raccoon.py <config_file>
```
## Authentication

When a username and password are used, note that a security token may also be required (if coming from an IP address outside any defined Network Access ranges). Refer to [this article](https://help.salesforce.com/articleView?id=user_security_token.htm&type=5) for more information.

Using the session ID alternative is useful in many cases:
* Single sign-on i.e. no direct login to Salesforce possible
* MFA is enforced
* Trouble getting an API token (when needed)
* Stops credentials accidentally being left in a file

To get the session ID:
* Log in to Salesforce and switch to Classic mode if need be
* Use the browser's Inspect tool to display the cookies
* Sometimes there are multiple `sid` cookies: ensure you grab the one whose `Domain` attribute includes `my.salesforce.com` or `cloudforce.com`

## Output

Sample (abridged and anonymised) output:

```
Raccoon - Salesforce object access auditor
- version 1.0
- https://www.github.com/nccgroup/raccoon
* Refer to README for usage notes including important limitations *

Target instance: somewhere.my.salesforce.com
- Login successful

4,969,529 API requests can be sent to this instance from a 24-hour limit of 5,000,000
- Up to 33 further requests are required to complete (3 requests sent so far)
- Do you want to continue? Enter 'y' to proceed: y

Validating objects
- Found object 'Accounts' with API name 'Account'
- Found object 'Contact' with API name 'Contact'
- Found object 'Quotes' with API name 'Quote__c'
- Found object 'Quote Lines' with API name 'QuoteLine__c'

Evaluating 28 Profiles and 104 Permission Sets
- Profiles with active users: 15
- Permission Sets with active users: 67
- Ignoring 50 unused Profiles and Permission Sets

Global Sharing Overrides (ALL records for ALL objects)
------------------------------------------------------

  READ/EDIT/DELETE                           [C]ustom Active/Total [G]uest[E]xt[I]nt
  Profiles
  - System Administrator                              61/91                    [I]

  READ
  Profiles
  - Integration User                         [C]      1/1                      [I]
  - Analytics Cloud Integration User                  1/1                      [I]

Object Sharing (ALL records for EACH object)
--------------------------------------------

Account:
  Organization-wide default sharing
  - Internal: Public Read Only
  - External: <Undefined>

  READ/EDIT/DELETE                           [C]ustom Active/Total [G]uest[E]xt[I]nt
  Profiles
  - Integration User                         [C]      1/1                      [I]
  Permission Sets (* Groups)
  - Mulesoft Integration                     [C]      2/2                      [I]

  READ
  Profiles
  - Read Only                                [C]      192/199                  [I]
  - Sales User                               [C]      192/248                  [I]
  - Finance User                             [C]      16/20                    [I]
  - Standard User                                     6/3075                   [I]
  Permission Sets (* Groups)
  * Accounts PS Group                        [C]      36/39                    [I]
  - Sales Operations                         [C]      24/26                    [I]
  - SharePoint User                          [C]      3/4                      [I]

  Sharing Rules (manual check required):
  - Criteria-based rules configured
  - Ownership-based rules configured

Contact:
  Organization-wide default sharing
  - Internal: Controlled by Parent
  - External: <Undefined>
  Parent object: 'Account'
  - Internal: Public Read Only
  - External: <Undefined>

  READ/EDIT/DELETE                           [C]ustom Active/Total [G]uest[E]xt[I]nt
  Profiles
  - Integration User                                  1/1                      [I]
  Permission Sets (* Groups)
  - Mulesoft Integration                     [C]      2/2                      [I]

  READ
  Profiles
  - Read Only                                [C]      192/199                  [I]
  - Sales User                               [C]      192/248                  [I]
  - Finance User                             [C]      16/20                    [I]
  - Standard User                                     6/3075                   [I]
  Permission Sets (* Groups)
  - Sales Operations                         [C]      24/26                    [I]

Quote__c:
  Organization-wide default sharing
  - Internal: Public Read/Write
  - External: <Undefined>

  READ/EDIT                                  [C]ustom Active/Total [G]uest[E]xt[I]nt
  Profiles
  - Sales User                               [C]      192/248                  [I]

  READ
  Profiles
  - Finance User                             [C]      16/20                    [I]
  Permission Sets (* Groups)
  - Mulesoft Integration                     [C]      2/2                      [I]

QuoteLine__c:
  Organization-wide default sharing
  - Internal: Controlled by Parent
  - External: <Undefined>
  Parent object: 'Quote__c'
  - Internal: Public Read/Write
  - External: <Undefined>

  READ/EDIT/DELETE                           [C]ustom Active/Total [G]uest[E]xt[I]nt
  Profiles
  - Sales User                               [C]      192/248                  [I]

  READ
  Profiles
  - Finance User                             [C]      16/20                    [I]
  Permission Sets (* Groups)
  - Mulesoft Integration                     [C]      2/2                      [I]

Total API requests sent: 31
```

Raccoon only examines Profiles and Permission Sets with active users to reduce the verbosity of its output. Information about this is displayed, after which:
* Global Sharing Overrides are displayed first since Profiles and Permission Sets that are allowed to 'View All Data' and 'Modify All Data' have rights over ALL objects.
* Each object is then audited in turn with read+edit+delete privileges considered first, then read+edit, and lastly just read. A Profile or Permission Set is only listed once within the output (in the section containing the highest set of effective permissions). This is to avoid repetition - for example, it is implicit that a Profile with 'Modify All Data' has read+edit+delete on all the objects specified; thus, it is only shown under "Global Sharing Overrides", it is not also listed under each object's results. The only exception is when Profiles or Permission Sets with the global 'View All Data' privilege have further edit/delete permissions enabled at the object level.
* For each object, the *existence* of Sharing Rules is highlighted but not qualified further.

If assignment of privileges has been granted through a Permission Set Group, as opposed to a single Permission Set, an asterisk appears as an indentation marker to the left of the name instead of the usual hyphen (`Accounts PS Group` in the above sample output). In addition, whether the Profile or Permission Set is custom is also shown (for Permission Sets custom means "created by an admin" otherwise it "is standard and related to a specific permission set license" [[ref](https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_permissionset.htm)]).

For both global and object sharing, Profiles and Permission Sets are ordered to reflect the likely interest. The first level of ordering concerns which type of user is assigned - 'guest' (unauthenticated) first, followed by 'external' (various types of portal user) then 'internal' (anything else). It is important to note that 'external' here is related to the definition used in the context of the 'external sharing model' [[ref](https://help.salesforce.com/articleView?id=sf.security_owd_external.htm&type=5)]. The idea here is to highlight potentially excessive sharing for unauthenticated or portal users. However, it is somewhat experimental because the Salesforce documentation is not comprehensive in its list of valid 'UserType' values for the 'User' object [[ref](https://developer.salesforce.com/docs/atlas.en-us.api.meta/api/sforce_api_objects_user.htm)]. As a result, it is possible that misclassification could occur - please [file an issue](#reporting-bugs) in such a case. The second level of ordering is based on the number of active users - highest first (the total number of assigned users is also displayed for information).

## Notes

Raccoon's primary objective is to highlight instances of widespread access to *all* records, and it covers:
* Master-Detail relationships where sharing is 'Controlled by Parent' (but only if there is a single Master-Detail relationship and the parent is directly above the child i.e. the parent's sharing model cannot also be 'Controlled by Parent').
* Special 'Controlled by Parent' relationships between Contact/Order/Asset and the parent Account (which work slightly differently to the normal Master-Detail relationship).
* To reiterate, only Profiles and Permission Sets with *active* users are considered.

The following factors, which affect only a *subset* of records, are *not* evaluated:
* Sharing Rules (although their *existence* for an object is flagged)
* Sharing Sets
* Share Groups
* Sharing based on Role hierarchy
* Manual sharing configured by users on individual records
* 'Implicit' (or 'built-in') sharing for certain children of Account when its sharing model is Private
* The 'private' field for an Opportunity record (and consequent effect on related Quotes)

Certain objects, such as 'User' and 'File', do not fit the standard sharing model and/or other system permissions come into play. Known instances are flagged in the output if they are specified in the `objects` list.

Instances with over 2,000 combined Profiles and Permission Sets are not supported due to platform limitations on the use of 'GROUP BY' in SOQL statements. This is a generous allowance and should only be a blocker in the most extreme cases.

### Account permissions

This tool only performs read operations. It might therefore be surprising to see '*Modify* Metadata Through Metadata API Functions' as a requirement for the account used to run the tool. However, at the time of writing, it does not appear possible to configure an account with read-only permissions to the Metadata API. From the [documentation](https://developer.salesforce.com/docs/atlas.en-us.226.0.api_meta.meta/api_meta/meta_quickstart_prereqs.htm):

> Identify a user that has the API Enabled permission and the Modify Metadata Through Metadata API Functions permission or Modify All Data permission. These permissions are required to access Metadata API calls. If a user requires access to metadata but not to data, enable the Modify Metadata Through Metadata API Functions permission. Otherwise, enable the Modify All Data permission.

It is therefore suggested that 'Modify Metadata Through Metadata API Functions' is used over 'Modify All Data'.

## Reporting bugs

If the problem is with login then please first double-check the hostname, username, password and security token (if required). Also consider if the password needs resetting (try the usual Salesforce web login) because this condition returns an error that is indistinguishable from an invalid login. If using a session ID, ensure it is valid for the correct domain.

Run the tool with `debug` set to `2`, as the verbose output may help to identify the cause. This level also outputs a stack trace to a file named in the output. If reporting an issue, please include both the console output and stack trace (anonymise as needed).

## Why 'Raccoon'?

Known for rummaging around objects.