#!/usr/bin/env python3
import sys
import os
import argparse
import seaborn as sns

values=[]
with open("latency.txt", "r") as filestream:
    # with open("answers.txt", "w") as filestreamtwo:
    for index, line in enumerate(filestream.readlines()):
        if(index%2==1):
            s=0
            count=0
            for num in line.strip().split(', '):
                try:
                    values.append(int(num))
                    s += int(num)
                    count+=1
                except:
                    print("line "+str(index)+"done")
            avg=s/count    
        else:
            timer=line.rsplit(" ", 1)[-1]
            
        # filestreamtwo.write(total)
filestream.close()
print(values[122])
sns.kdeplot(data = values, label="Latency", cumulative = True)
# sns.show()
