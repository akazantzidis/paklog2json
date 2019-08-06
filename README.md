***Info:***

paklog2json.py is a python script which does listen to a specific port/interface protocol(tcp/udp)  and get’s the output of a cisco ss7 itp paklog(udp stream) ,transforms it to json per msu and sends it to another tcp/udp-host/port endpoint(like graylog for monitor/debug purposes).

You can get it with:

    git clone https://github.com/akazantzidis/paklog2json.git

***Usage :***

    python paklog2json.py -p PORT -proto TCP/UDP -i INTERFACE --d syslog --sip $DST_IP -sport DST_PORT -sproto TCP/UDP

***Explanation of arguments:***

    '-p' , '--listen_port'  = port to listen to.       
    '-proto' , '--listen_protocol = protocol to listen at  '['tcp','udp'],'-i' , '--interface' = network interface to listen to.
    '-d' , '--decode_as' , = in which form is encoded the original stream.(for more info check tshark -d option).
    '-sip' , '--send_to_ip' = destination host ip address.
    '-sport' , '--send_port' = destination host port to send to.
    '-sproto' , '--send_protocol = destination host listen protocol ['tcp','udp'].

***Example:***

 Assume that i want to run as:

 Listen on “udp port 80 interface eth0”,on my server for paklog input,
 and  send the created json stream “to 1.1.1.1 tcp 80 decoded as syslog”,

i would:

    ./paklog2json.py -p 80 -i  eth0 -p udp -d syslog -sip 1.1.1.1 -sport 80 -sproto tcp

**
