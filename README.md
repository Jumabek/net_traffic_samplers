This repo is C++ version of intrusion-sampling


Datasets we are using [ISCX-2014-Bot, CIC-IDS-2017,CIC-IDS-2018](https://www.unb.ca/cic/datasets/) comes with [80 flow features](http://www.netflowmeter.ca/netflowmeter.html)
Among them we can estimate 9 of them with samplers, because other time related feautures such as IAT(InterArrivalTime) of neightboring packets cannot be estimated. 
Although for sketchflow we can calculate IAT of two packets and divide them by sampling rate, it might be considered unfair because other samplers cannot estimate it well.  


**Sketchflow**


**Compiling**
`g++ -std=c++11 -o sketchflow sketchflow.cpp collector.cpp helper.c -lm -lpcap -lpthread -msse4.2`

**Call**
 `python scripts/sample_ids-2018_sketchflow.py`
 
 <br />


**sFlow**

**Compiling**
`g++ -std=c++11 -o sflow sflow.cpp collector.cpp helper.c -lm -lpcap -lpthread -msse4.2`

**Call**
 `python scripts/sample_ids-2018_sflow.py` 

 <br />


**SGS**

**Compiling**
`g++ -std=c++11 -o sgs sgs.cpp collector.cpp helper.c -lm -lpcap -lpthread -msse4.2`

**Call**
 `python scripts/sample_ids-2018_sgs.py` 

<br />



**Fast Filtered Sampling**

**Compiling**
`g++ -std=c++11 -o ffs ffs.cpp collector.cpp helper.c -lm -lpcap -lpthread -msse4.2`

**Call**
 `python scripts/sample_ids-2018_ffs.py` 


**Selective Flow Sampling**

**Compiling**
`g++ -std=c++11 -o selective_flow selective_flow.cpp collector.cpp helper.c -lm -lpcap -lpthread -msse4.2`

**Call**
 `python scripts/sample_ids-2018_selective_flow.py` 