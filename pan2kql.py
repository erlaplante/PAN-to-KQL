# PAN-to-KQL

from datetime import datetime
import re
import sys
import pyperclip

# PAN filter to Kusto query dictionary
translation = {'neq ': '!= ',
               'notin ': '!= ',
               'eq ': '== ',
               'in ': '== ',
               'rule ': 'Rule ',
               'action ': 'DeviceAction ',
               'addr.src ': 'SourceIP ',
               'addr.dst ': 'DestinationIP ',
               'port.src ': 'SourcePort ',
               'port.dst ': 'DestinationPort ',
               'user.src ': 'SourceUserName ',
               'zone.src ': 'SourceZone ',
               'zone.dst ': 'DestinationZone ',
               'session_end_reason ': 'reason ',
               'proto ': 'Protocol ',
               'app ': 'ApplicationProtocol ',
               'subtype ': 'DeviceEventClassID ',
               'natsrc ': 'SourceTranslatedAddress ',
               'natdst ': 'DestinationTranslatedAddress ',
               'device_name ': 'DeviceName '}

# accepts datetime string and returns its converted UTC datetime string
def convert_to_utc(date_str):
    dt_obj = datetime.strptime(date_str, '%Y/%m/%d %H:%M:%S')
    timestamp = datetime.timestamp(dt_obj)
    utc_date_str = str(datetime.utcfromtimestamp(timestamp))
    return utc_date_str

query = input('Enter PAN filter to translate:\n  ')

# check for time conversion and validate format
if 'time_generated' in query or 'receive_time' in query:
    time_btwn_regex = re.compile(r'\(\s*(?:time_generated|receive_time) geq \'(\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)\'.*\)\s+and\s+\(.*(?:time_generated|receive_time) leq \'(\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)\'\s*\)')
    mo = time_btwn_regex.search(query)
    
    incorrectTimeMsg = ("\nIncorrect PAN time format:\n\n"
                        "Must use \"( time_generated geq 'YYYY/MM/DD hh:mm:ss' ) and ( time_generated leq 'YYYY/MM/DD hh:mm:ss' )\" in this order to search between times.\n"
                        "Or a single \"time_generated geq <OR> leq\", \"receive_time\" is also accepted, both translated to \"TimeGenerated\".")

    # match object has "greater than or equal" and "less than or equal" date-times in PAN filter in correct order
    # assign both variables and do UTC conversion
    if mo is not None:
        geq_date_str, leq_date_str = mo.groups()

        geq_utc_str = convert_to_utc(geq_date_str)
        leq_utc_str = convert_to_utc(leq_date_str)
        
        query = time_btwn_regex.sub(r"TimeGenerated between(datetime('" + geq_utc_str + "') .. datetime('" + leq_utc_str + "'))", query)
    else:
        # check for single datetime in filter/query
        singular_check_regex = re.compile(r'(time_generated|receive_time)')
        matches = singular_check_regex.findall(query)
        if len(matches) > 1:
            sys.exit(incorrectTimeMsg)
        else:
            singular_time_regex = re.compile(r'(?:time_generated|receive_time) ([gl]eq) \'(\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)\'')
            mo = singular_time_regex.search(query)
            # single datetime in correct PAN format
            if mo is not None:
                equality, single_date_str = mo.groups()
                if equality.startswith('g'):
                    equality = '>='
                else:
                    equality = '<='
                single_utc_str = convert_to_utc(single_date_str)
                query = singular_time_regex.sub(r'TimeGenerated ' + equality + ' todatetime(\'' + single_utc_str + '\')', query)
            else:
                sys.exit(incorrectTimeMsg)

# swap each key with value from translation dictionary
for key in translation.keys():
    if key in query:
        query = query.replace(key, translation[key])

# translate PAN "addr (not)in" to use Source or Destination IP in KQL,
# regex looks for ending ")" so in this case adds in single quotes around SourceIP
addrin = re.compile(r'addr (==|!=) (\'?(\d{1,3}\.){3}\d{1,3}\'?(\/\d{1,2})?)')
mo = addrin.search(query)
if mo is not None:
    if mo.group(1) == '==':
        query = addrin.sub(r"SourceIP \1 '\2' or DestinationIP \1 \2", query)
    else:
        query = addrin.sub(r"not(SourceIP == '\2' or DestinationIP == \2)", query)

# add single quotes around KQL declaration
addQuotes = re.compile(r'([!=]= )([^ \)]+)( ?\))')
query = addQuotes.sub(r"\1'\2'\3", query)

# cleanup potential consecutive single quotes
query = query.replace("''", "'")

# add "@" to use verbatim string literal in down-level logon name (Domain\SAMAccountName)
strLiteral = re.compile(r"('\w+\\)([\w\.]+')")
query = strLiteral.sub(r"@\1\\\2", query)

# CIDR translation
cidr = re.compile(r"(not\()?(SourceIP|DestinationIP) ([!=]=) ('(\d{1,3}\.){3}\d{1,3}\/\d{1,2}')")
mo = cidr.search(query)
if mo is not None:
    if mo.group(3) == '!=':
        query = cidr.sub(r'not(ipv4_is_match(\2, \4))', query)
    else:
        query = cidr.sub(r'\1ipv4_is_match(\2, \4)', query)

pyperclip.copy(query)
print('\nTranslation (copied to clipboard):\n  ' + query)
