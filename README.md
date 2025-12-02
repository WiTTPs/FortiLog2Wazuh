# FortiLog2Wazuh
collection of tools to parse FortiOS Logs to Wazuh

The builtin Wazuh rules for the FortiOS devices arent as good as I would like them to be.
So the idea was use the FortiOS Log Message Reference document as a base to generate a new ruleset.
Sadly the Log Message Reference is only available via the website or as a PDF file. 
Fortinet support also said there is no option to get the data in a different format.
So my approach was to parse the data directly from the PDF file.


## Parsing the Log Types from the PDF
fortilogparse.py can be used to read the data from the file and save the different message IDs with the base description as a JSON file.

usage:
``` python
python fortilogparse.py FortiOS_7.2.12_Log_Reference.pdf FortiOSLogs7_2_12.json
```

Example output:
```
        {
            "Message ID": "13712",
            "Message Description": "LOG_ID_VIDEOFILTER_TITLE_BLOCK",
            "Message Meaning": "Video title is blocked.",
            "Type": "Webfilter",
            "Category": "videofilter-title",
            "Severity": "Warning"
        },

```
## Generate Ruleset based on JSON file

The next step is to use the JSON file to generate a Wazuh ruleset.
usage:
``` python
python generate_wazuh_rules.py FortiOSLogs7_2_12.json FortiOSLog_rules.xml
```
In the python script you can also adjust the mapping of the FortiOS severity types to Wazuh rule levels

Example output:

```
<group name="fortigate-rules">
    <rule id="100010" level="4">
        <decoded_as>fortinet-fortigate-firewall</decoded_as>
        <description>Fortigate messages grouped</description>
    </rule>
    <rule id="100011" level="7">
        <!-- 18432 -->
        <field name="logid">18432$</field>
        <description>Attack detected by UDP/TCP anomaly</description>
        <group>fortios.event.anomaly,fortios.category.anomaly,fortios.severity.alert</group>
    </rule>
```

copy the file to /var/ossec/etc/rules

## Custom decoder

Next step is to build a custom decoder. alextibor already has a good decoder which I used as a base.

https://github.com/alextibor/wazuh-fortigate-rules-decoders


The only adjustment was to use the logid field and split it up into the different components.

Log ID definitions

First 2 digits: log_type
- Traffic log IDs begin with "00"
- Event log IDs begin with "01"

next 2 digits:
- "00" => 'forward' subtype.
- "01" => 'VPN' subtype.

last 6 digits:
"000013" => message ID as referenced by the documentation

```
<decoder name="fortinet-fortigate-firewall">
  <prematch type="pcre2">^date=\d{4}-\d{2}-\d{2}\s+time=\d{2}:\d{2}:\d{2}\s+devname="[^"]*"\s+devid="[^"]*"\s+eventtime=\d+\s+tz="[^"]*"\s+logid="\d+"</prematch>
</decoder>

<decoder name="fortinet-fortigate-firewall">
  <parent>fortinet-fortigate-firewall</parent>
  <regex>devname="(\.*)"|devname=(\.*)\s|devname=(\.*)$</regex>
  <order>devname</order>
</decoder>

<decoder name="fortinet-fortigate-firewall">
  <parent>fortinet-fortigate-firewall</parent>
  <regex type="pcre2">logid="((\d{2})(\d{2})(\d{6}))\d*"</regex>
  <order>logid, log_type, log_subtype, message_id</order>
</decoder>
...
```

copy the file to /var/ossec/etc/decoders

Test with sample syslog entry and
```
/var/ossec/bin/wazuh-logtest
```

To reduce to log volume you can also mute certain rules by adjusting the rules and setting the level to 0.
Use with caution though, as you might miss valuable traffic info.
Example:
Mute Forward traffic Message ID 13 - LOG_ID_TRAFFIC_END_FORWARD
 ```
 <rule id="110000" level="0">
        <!-- CUSTOM RULE 13 -->
        <if_sid>100010</if_sid>
        <field name="logid">0000000013$</field>
        <description>LOG_ID_TRAFFIC_END_FORWARD</description>
        <group>fortios.event.unknown-ce,fortios.category.unknown-ce,fortios.severity.warning</group>
    </rule>
```

You could also filter on dstintf or srcintf if needed with the same method.
