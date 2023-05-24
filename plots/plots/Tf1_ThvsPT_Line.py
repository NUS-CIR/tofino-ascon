import numpy as np
import matplotlib.pyplot as plt
plt.rcParams.update({'font.size': 11})
fig = plt.subplots(figsize =(12, 8))
y = np.array([4.99,4.99, 4.25,4.25, 3.567,3.567,3.07])
x = np.array([64,127,128,191,192,255,256])
x_2=np.array([64,128,192,256])
# plt.title("Tofino-1 Throughput vs Plaintext Size", fontweight ='bold', fontsize = 15)
plt.xlabel("Plaintext Length(in bits)", fontweight ='bold', fontsize = 13)
plt.ylabel("Throughput(in Mpps)", fontweight ='bold', fontsize = 13)

plt.plot(x, y,'o-k',mfc='r')
plt.xticks(x_2)
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