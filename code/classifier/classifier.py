import torch
import torchvision
import torchvision.transforms as transforms
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import torch.optim as optim

#这里因为我的电脑上import plt会core dump,所以添加这两句话切换后端
import matplotlib as mpl
mpl.use('TkAgg')  # or whatever other backend that you want,

import matplotlib.pyplot as plt

#先将图片转换成tensor，然后进行标准化(z-score)
transform = transforms.Compose([
    transforms.ToTensor(),
    transforms.Normalize(mean=(0.5,0.5, 0.5), std=(0.5,0.5,0.5))
])

trainset = torchvision.datasets.CIFAR10(root='./data', train=True, 
                                        download=True, transform=transform)
print("len of trainset:%d" % (len(trainset)))                                        
trainloader = torch.utils.data.DataLoader(trainset, batch_size=4, shuffle=True, num_workers=2)

testset = torchvision.datasets.CIFAR10(root='./data', train=False, download=True, transform=transform)
print("len of testset:%d" % (len(testset)))   
testloader = torch.utils.data.DataLoader(testset, batch_size=4, shuffle=False, num_workers=2)

classes = ('plane', 'car', 'bird', 'cat',
           'deer', 'dog', 'frog', 'horse', 'ship', 'truck')

def imshow(img):
    img = img / 2 + 0.5 #unnormalize
    npimg = img.numpy() #(c,w,h)
    plt.imshow(np.transpose(npimg,(1,2,0)))#(w,h,c)
    plt.show()
def random_show_a_image_in_trainset():
    data_it = iter(trainloader)
    images, labels = data_it.next()
    print(' '.join('%5s' % classes[labels[j]] for j in range(4)))
    grid = torchvision.utils.make_grid(images)
    imshow(grid)
# 下面用两种方法实现了同样结构的网络
class Net(nn.Module):
    def __init__(self):
        super(Net, self).__init__()
        self.conv1 = nn.Conv2d(3,6,5)
        self.pool = nn.MaxPool2d(2,2)
        self.conv2 = nn.Conv2d(6,16,5)
        self.fc1 = nn.Linear(16*5*5, 120)
        self.fc2 = nn.Linear(120,84)
        self.fc3 = nn.Linear(84,10)
    def forward(self, x):
        x = self.pool(F.relu(self.conv1(x)))
        x = self.pool(F.relu(self.conv2(x)))
        x = x.view(-1, 16*5*5)
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        x = self.fc3(x)
        return x

class Net2(nn.Module):
    def __init__(self):
        super(Net2, self).__init__()
        self.convs = nn.Sequential(
            nn.Conv2d(3,6,5),
            nn.ReLU(),
            nn.MaxPool2d(2,2),
            nn.Conv2d(6,16,5),
            nn.ReLU(),
            nn.MaxPool2d(2,2)
        )
        self.fcs = nn.Sequential(
            nn.Linear(16*5*5, 120),
            nn.ReLU(),
            nn.Linear(120,84),
            nn.ReLU(),
            nn.Linear(84,10)
        )
    def forward(self,x):
        x = self.convs(x)
        x = x.view(-1, 16*5*5)
        x = self.fcs(x)
        return x


device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

def train_model():
    net = Net2()
    print(device)
    net.to(device)
    # loss函数
    criterion = nn.CrossEntropyLoss()
    # 优化器
    optimizer = optim.SGD(net.parameters(), lr = 0.001, momentum=0.9)

    for epoch in range(2):
        running_loos = 0.0
        for i, data in enumerate(trainloader,start=0):
            inputs, labels = data
            inputs, labels = inputs.to(device), labels.to(device)

            optimizer.zero_grad()

            outputs = net(inputs)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
            running_loos += loss.item()
            if i % 2000 == 1999:
                print('[%d, %5d] loss: %.3f' % (epoch + 1, i+1, running_loos/2000))
                running_loos = 0.0
    print('Finish traing')
    return net


do_train = False

if do_train:
    print("do train")
    net = train_model()
    torch.save(net, "./classifier.pt")
    print("save model success")
else:
    print("do test")
    net = torch.load("./classifier.pt")
    print("load net success")
    correct = 0
    total = 0

    with torch.no_grad():
        for data in testloader:
            images, labels = data
            images, labels = images.to(device), labels.to(device)
            outputs = net(images)
            _, predicted = torch.max(outputs, 1)
            total += labels.size(0)
            correct += (predicted == labels).sum().item()
        print('Accuracy of the network on the 10000 test images: %d %%' % (
        100 * correct / total))

#random_show_a_image_in_trainset()