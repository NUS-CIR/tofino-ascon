import numpy as np
import matplotlib.pyplot as plt

# set width of bar
barWidth = 0.16
fig = plt.subplots(figsize =(12, 8))
 
# set height of bar
tf1 = [4.99, 4.25, 3.55,3.07]
# tf2 = [39.35,35.88,30.88,25.41]
tf2 = [21.4,17.94,14.96,12.7]
 
# Set position of bar on X axis
br1 = np.arange(len(tf1))
br2 = [x + barWidth for x in br1]

 
# Make the plot
plt.bar(br1, tf1, color ='b', width = barWidth,
        edgecolor ='grey', label ='Tofino1')
plt.bar(br2, tf2, color ='violet', width = barWidth,
        edgecolor ='grey', label ='Tofino2')

 
# Adding Xticks
plt.xlabel('Plaintext Length(in bits)', fontweight ='bold', fontsize = 13)
plt.ylabel('Throughput(in Mil. Packets/sec)', fontweight ='bold', fontsize = 13)
plt.xticks([r + barWidth/2 for r in range(len(tf1))],
        [64,128,192,256])
plt.title("Combined(2 ASCON rounds/pass) Throughput vs Plaintext Length", fontweight ='bold', fontsize = 15)
plt.legend()
plt.show()