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

