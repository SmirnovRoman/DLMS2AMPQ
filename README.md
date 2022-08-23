# DLMS2AMPQ 
Proof of concept project of reading DLMS smart meters through AMPQ server

Supported commands 

1. 
> DLMS2AMPQ 

without parameters reads configuration and proceed commands read from MQ queue and translated to DLMS

2. 
> DLMS2AMPQ send file_with_request.json

send request from file to input queue

3. 
> DLMS2AMPQ dump 

dump replyes from out queue

### Configuration json
>
{
  "HostName": "172.17.230.131",  // hostname of RabbitMQ server
  "Port": 5672, // port of RabbitMQ server
  "VirtualHost": "HEX", // virtual host on RabbitMQ server
  "UserName": "adm", // user name used to access of RabbitMQ server
  "Password": "test", // password used to access of RabbitMQ server
  "DebugFile": "log.txt",   // Debug file
  "InQueue": "INDLMS", // Queue on server which is monitored for incoming commands
  "OutQueue": "OUTDLMS" // Queue on server where data are put
}


### **Format of message with commands**
>
{
  "MsgID": "1443", // - unique message id - will be put into reply
  "Cmd": "READ", // command - at the moment only READ supported
  "ObisCode": "1.0.99.1.0.255", // - OBIS code to request
  "ConnectionString": "-h 127.0.0.1 -p 4060 -c 32 -a Low -i WRAPPER -P 00000000", // connection string in format described below
  "dtFrom": "2022-08-17T18:01:57.9123297+03:00", // data from 
  "dtTo": "2022-08-22T18:01:57.9269498+03:00" // data to
}


### **Format of Reply**/
>
{
  "InMsgID": "1443", // - request message id 
  "MsgID": "ba21630b-07af-43b1-b286-54b94f61b268", // unique message id of reply 
  "Status": "ok", // statu - ok or notok
  "Error": "", // description of error in GURUX lib
  "DataRecords": [ // data records
    {
      "DateTime": "12/15/2020 9:00:00.010 PM",
      "Code": "0",  // obis code
      "Value": "1134573"
    },   
    {
      "DateTime": "12/15/2020 12:00:00.010 AM",
      "Code": "0",
      "Value": "1058976"
    }
  ]
}

### ** Example of error message ** 
>
{
  "InMsgID": "1443",
  "MsgID": "344eb4be-6e2e-4e9f-8c52-f41e8fef90fc",
  "Status": "notok",
  "Error": "Connection is permanently rejected. Authentication failure.",
  "DataRecords": []
}

## Connection settings (parameter ConnectionString in request command )

Example:  -h [Meter IP Address] -p [Meter Port No] -c 16 -s 1 -r SN

             -h host name or IP address.
             -p  port number or name (Example: 1000).
             -S [COM1:9600:8None1] serial port.
             -a  Authentication (None, Low, High).
             -P  Password for authentication.
             -c  Client address. (Default: 16)
             -s  Server address. (Default: 1)
             -n  Server address as serial number.
             -l  Logical Server address.
             -r [sn, ln] Short name or Logical Name (default) referencing is used.
             -t [Error, Warning, Info, Verbose] Trace messages.
             -g \"0.0.1.0.0.255:1; 0.0.1.0.0.255:2\" Get selected object(s) with given attribute index.
             -C  Security Level. (None, Authentication, Encrypted, AuthenticationEncryption)
             -V  Security Suite version. (Default: Suite0). (Suite0, Suite1 or Suite2)
             -K  Signing (None, EphemeralUnifiedModel, OnePassDiffieHellman or StaticUnifiedModel, GeneralSigning).
             -v  Invocation counter data object Logical Name. Ex. 0.0.43.1.1.255
             -I  Auto increase invoke ID
             -o  Cache association view to make reading faster. Ex. -o C:\\device.xml 
             -T  System title that is used with chiphering. Ex -T 4775727578313233
             -M  Meter system title that is used with chiphering. Ex -T 4775727578313233
             -A  Authentication key that is used with chiphering. Ex -A D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF
             -B  Block cipher key that is used with chiphering. Ex -B 000102030405060708090A0B0C0D0E0F
             -D  Dedicated key that is used with chiphering. Ex -D 00112233445566778899AABBCCDDEEFF
             -F  Initial Frame Counter (Invocation counter) value.
             -d  Used DLMS standard. Ex -d India (DLMS, India, Italy, SaudiArabia, IDIS)
             -E  Export client and server certificates from the meter. Ex. -E 0.0.43.0.0.255.
             -N  Generate new client and server certificates and import them to the server. Ex. -R 0.0.43.0.0.255.
             -G  Use Gateway with given NetworkId and PhysicalDeviceAddress. Ex -G 0:1.
             -i  Used communication interface. Ex. -i WRAPPER.
             -m  Used PLC MAC address. Ex. -m 1.
             -G  Gateway settings NetworkId:PhysicalDeviceAddress. Ex -G 1:12345678
             -W  General Block Transfer window size.
             -w  HDLC Window size. Default is 1
             -f  HDLC Frame size. Default is 128
             -L  Manufacturer ID (Flag ID) is used to use manufacturer depending functionality. -L LGZ
            
            Examples:

            Read LG device using TCP/IP connection.
            -r SN -c 16 -s 1 -h [Meter IP Address] -p [Meter Port No]

            Read LG device using serial port connection.
            -r SN -c 16 -s 1 -sp COM1

            Read Indian device using serial port connection.
            -S COM1 -c 16 -s 1 -a Low -P [password]

## Load tests

1. Setup RabbitMQ

apt install rabbitmq-server

rabbitmq-plugins enable rabbitmq_management
rabbitmqctl add_user adm test
rabbitmqctl set_user_tags adm administrator
rabbitmqctl add_vhost HEX
rabbitmqctl set_permissions -p HEX adm ".*" ".*" ".*"


2. Setup configuration for DLMS2AMPQ

{
  "HostName": "172.17.230.131",  // hostname of RabbitMQ server
  "Port": 5672, // port of RabbitMQ server
  "VirtualHost": "HEX", // virtual host on RabbitMQ server
  "UserName": "adm", // user name used to access of RabbitMQ server
  "Password": "test", // password used to access of RabbitMQ server
  "DebugFile": "log.txt",   // Debug file
  "InQueue": "INDLMS", // Queue on server which is monitored for incoming commands
  "OutQueue": "OUTDLMS" // Queue on server where data are put
}

3. Starting 10.000 of emulator instances

#!/bin/bash
for i in {20000..30000}
do
   nohup ./Gurux.DLMS.Simulator.Net -i WRAPPER -N 1 -p $i -t Verbose -x mir.xml > simulator_logs/$i &
done

4. Starting DLMS2AMPQ daemon

DLMS2AMPQ

5. Test sending reading request

#!/bin/bash
mkdir "requests"
for i in {20000..30000}
do
read -r -d '' MSG << EOM
{
  "MsgID": "$i",
  "Cmd": "READ",
  "ObisCode": "1.0.99.1.0.255",
  "ConnectionString": "-h 127.0.0.1 -p $i -c 32 -a Low -i WRAPPER -P 00000000",
  "dtFrom": "2020-12-15T00:00:00.00+03:00",
  "dtTo": "2020-12-16T00:00:00.00+03:00"
}
EOM
echo $MSG > "requests/$i"
DLMS2AMPQ send requests/$i
done

6. Read replies 

DLMS2AMPQ dump

7. Review throughput parameters in rabbitmq


Sources of Gurux included ( modified to exclude some parts as nuget packages , target net60 ) , also included image for simulator - mir.xml