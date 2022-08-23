#!/bin/bash
for i in {20000..30000}
do
   nohup ./Gurux.DLMS.Simulator.Net -i WRAPPER -N 1 -p $i -t Verbose -x mir.xml > simulator_logs/$i &
done

