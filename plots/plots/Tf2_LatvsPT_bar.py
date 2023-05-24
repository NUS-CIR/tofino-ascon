import numpy as np
import matplotlib.pyplot as plt

plt.rcParams.update({'font.size': 11})
barWidth = 0.16
fig = plt.subplots(figsize =(12, 8))

# set height of bar
8.41,9.26,10.55,11.94
rd1 = [25.79,30.26,36.72,42.66]
rd2 = [13.75,16.09,19.18,22.39]
rd3 = [9.79,11.35,13.42,14.89]
rd4 = [8.41,9.26,10.55,11.94]
x= [64,128,192,256]

err = [0.0059,0.0083,0.00704,0.00661]
err_2 = [0.01482,0.001012,0.00859,0.12652] 
err_3 = [0.00751,0.00522,0.0296,0.00760] 
err_4 = [0.00551,0.00849,0.00847,0.00725] 

# Set position of bar on X axis
br1 = np.arange(len(rd1))
br2 = [x + barWidth for x in br1]
br3 = [x + 2*barWidth for x in br1]
br4 = [x + 3*barWidth for x in br1]


# Make the plot
plt.bar(br1, rd1, color ='green', width = barWidth,
        edgecolor ='grey', label ='1 Round/Pass')
plt.bar(br2, rd2, color ='orange', width = barWidth,
        edgecolor ='grey', label ='2 Rounds/Pass')
plt.bar(br3, rd3, color ='blue', width = barWidth,
        edgecolor ='grey', label ='3 Rounds/Pass')
plt.bar(br4, rd4, color ='pink', width = barWidth,
        edgecolor ='grey', label ='4 Rounds/Pass')

# Adding Xticks
plt.xlabel('Plaintext Length(in bits)', fontweight ='bold', fontsize = 13)
plt.ylabel('Latency(in us)', fontweight ='bold', fontsize = 13)
plt.xticks([r + barWidth for r in range(len(rd1))],
        [64,128,192,256])

plt.errorbar(br1, rd1, yerr=err, fmt=" ", color="k") 
plt.errorbar(br2, rd2, yerr=err_2, fmt=" ", color="k") 
plt.errorbar(br3, rd3, yerr=err_3, fmt=" ", color="k") 
plt.errorbar(br4, rd4, yerr=err_4, fmt=" ", color="k") 
plt.legend(fontsize = 15)
# plt.title("Tofino2 Latency vs Plaintext Length", fontweight ='bold', fontsize = 15)
plt.show()