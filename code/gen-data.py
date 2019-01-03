import torch
import matplotlib as mpl
mpl.use('TkAgg')  # or whatever other backend that you want,
import matplotlib.pyplot as plt

x = torch.unsqueeze(torch.linspace(-1,1,100), dim = 1)
y = x.pow(2) + 0.2 *torch.rand(x.size())
print(x.size())
print(y.size())
print(x.numpy().shape)
print(y.numpy().shape)
plt.scatter(x.numpy(), y.numpy())
plt.show()
print(x.size())