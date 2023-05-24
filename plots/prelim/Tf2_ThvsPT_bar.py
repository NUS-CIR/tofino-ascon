import numpy as np
import matplotlib.pyplot as plt
y = np.array([39.35,35.88,30.88,25.41])
# x = np.array([64,127,128,191,192,255,256])
x=np.array([64,128,192,256])
plt.title("Tofino-1 Throughput vs Plaintext Size")
plt.xlabel("Plaintext Length(in bits)")
plt.ylabel("Throughput(in Mpps)")

plt.bar(x, y,color= "black",width=16)
plt.xticks(x)
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