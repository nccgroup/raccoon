# Change log

Not exhaustive (line references from _previous_ version).

## v1.1

### Bug fixes

* Lines 290-291 did not display error message correctly
* Line 572 exception needed for Quote whose Opportunity Master-Detail field is (anomalously) missing `referenceTo` (effective value is 'Opportunity')
* Line 579 exception needed for Quote whose Opportunity Master-Detail field is (anomalously) missing `writeRequiresMasterRead` (effective value is 'False')
* Line 579 not fatal but no default value for read_allows_write

### Improvements

* Added ability to authenticate using session ID to handle SSO and/or MFA (refer to `README`)
  * Added `sessionId` to `config.json` file
* Line 286 improved matching logic to catch supplied object name missing both '__c' suffix and namespace
* Results show object 'label' (friendly name) as well as API name (if different)