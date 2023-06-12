#!/usr/bin/env python3
import sys
import os
import argparse
import seaborn as sns
import matplotlib.pyplot as plt
tf1=[]
tf2=[]
with open("latency.txt", "r") as filestream:
    # with open("answers.txt", "w") as filestreamtwo:
    for index, line in enumerate(filestream.readlines()):
        if(index%2==1):
            s=0
            count=0
            for num in line.strip().split(', '):
                try:
                    tf1.append(int(num))
                    s += int(num)
                    count+=1
                except:
                    print("line "+str(index)+" done")
            avg=s/count    
        else:
            timer=line.rsplit(" ", 1)[-1]
            
        # filestreamtwo.write(total)
filestream.close()
# print(len(tf1[]))
# tf1=tf1[:len(tf1)-1300]
with open("latency.txt", "r") as filestream:
    # with open("answers.txt", "w") as filestreamtwo:
    for index, line in enumerate(filestream.readlines()):
        if(index%2==1):
            s=0
            count=0
            for num in line.strip().split(', '):
                try:
                    tf1.append(int(num))
                    s += int(num)
                    count+=1
                except:
                    print("line "+str(index)+" done")
            avg=s/count    
        else:
            timer=line.rsplit(" ", 1)[-1]
            
        # filestreamtwo.write(total)
filestream.close()
# print(len(tf1[]))
# tf1=tf1[:len(tf1)-1300]

sns.kdeplot(data = tf1, cumulative = True,label="Latency")
plt.show()
