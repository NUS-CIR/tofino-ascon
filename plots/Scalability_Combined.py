import numpy as np
import matplotlib.pyplot as plt

fig = plt.subplots(figsize =(12, 8))

tf1 = np.array([4.99,10.12,20.16,39.35])
tf2 = np.array([39.35,78.7,160.72,320.23])
x = np.array([1,2,4,8])
# plt.title("Tofino 1 & 2 Throughput Scaling vs No. of Recirculating ports", fontweight ='bold', fontsize = 15)
plt.xlabel("No. of Recirculating ports", fontweight ='bold', fontsize = 13)
plt.ylabel("Throughput(in Mpps)", fontweight ='bold', fontsize = 13)

plt.plot(x, tf2,'o-b',mfc='green',label="Tofino2")
plt.plot(x, tf1,'o-m',mfc='red',label="Tofino1")

plt.xticks(x, fontsize = 11)
plt.yticks([5,39,50,100,150,200,250,300,250], fontsize = 11)
# plt.vlines(x, 0, y, linestyle="dashed")
plt.hlines([4.99,39.35], 0, [1,8] , linestyle="dashed",color='k')
plt.xlim(0,None)
plt.ylim(0,None)
plt.legend(fontsize = 15)
plt.show()

# import numpy as np
# import matplotlib.pyplot as plt

# x = np.linspace(0, 20, 1000)
# y1 = np.sin(x)
# y2 = np.cos(x)

# plt.plot(x, y1, "-b", label="sine")
# plt.plot(x, y2, "-r", label="cosine")
# plt.legend(loc="upper left")
# plt.ylim(-1.5, 2.0)
# plt.show()