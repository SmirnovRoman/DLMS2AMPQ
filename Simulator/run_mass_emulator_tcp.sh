#!/bin/bash
mkdir "simulator_logs"
for i in {20000..20050}
do
   nohup ./Gurux.DLMS.Simulator.Net -i WRAPPER -N 1 -p $i -t Verbose -x mir.xml > simulator_logs/$i &
done

