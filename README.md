## PAN-to-KQL

Translates a Palo Alto Networks (PAN) filter to Kusto Query Language (KQL). Typical use case would involve searching with a PAN filter, then translating to KQL if further analysis is desired. Minimal input validation is done as use case relies on PAN filter catching syntax violations. Currently only supports PAN traffic filters.

##### Features:
* Extensible dictionary mapping of commonly used PAN filter categories.
* Converts local time to UTC.
* Supports CIDR notation with KQL `ipv4_is_match`
* Two versions provided for flexibility or personal preference (Python and Go).

##### Requirements:
pyperclip (Python)\
clipboard (Go)
