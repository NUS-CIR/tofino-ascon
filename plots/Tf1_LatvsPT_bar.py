import numpy as np
import matplotlib.pyplot as plt

plt.rcParams.update({'font.size': 11})
barWidth = 0.16
fig = plt.subplots(figsize =(12, 8))

# set height of bar
rd1 = [23.33,27.28,31.1,34.85]
rd2 = [12.23,13.86,16.06,17.93]
x= [64,128,192,256]

err=[0.0195,0.0058,0.0229,0.00824]
err_2=[0.009,0.019,0.16667,0.032] 
# Set position of bar on X axis
br1 = np.arange(len(rd1))
br2 = [x + barWidth for x in br1]


# Make the plot
plt.bar(br1, rd1, color ='blue', width = barWidth,
        edgecolor ='grey', label ='1 Round/Pass')
plt.bar(br2, rd2, color ='magenta', width = barWidth,
        edgecolor ='grey', label ='2 Rounds/Pass')


# Adding Xticks
plt.xlabel('Plaintext Length(in bits)', fontweight ='bold', fontsize = 13)
plt.ylabel('Latency(in us)', fontweight ='bold', fontsize = 13)
plt.xticks([r + barWidth/2 for r in range(len(rd1))],
        [64,128,192,256])

plt.errorbar(br1, rd1, yerr=err, fmt=" ", color="k") 
plt.errorbar(br2, rd2, yerr=err_2, fmt=" ", color="k") 
plt.legend(fontsize=15)
# plt.title("Tofino1 Latency vs Plaintext Length", fontweight ='bold', fontsize = 15)
plt.show()