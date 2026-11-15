import os
import glob
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import TensorDataset,DataLoader
from spikingjelly.activation_based import functional
from snn_model import AISX2SNN

PROJECT_ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_FOLDER=os.path.join(PROJECT_ROOT,"data","Train")

def load_event_tensor(file_path):
    with open(file_path,"rb") as f:
        raw_data=f.read()
    EVENT_SIZE=5
    num_events=len(raw_data)//EVENT_SIZE
    x=np.zeros(num_events,dtype=np.int16)
    y=np.zeros(num_events,dtype=np.int16)
    polarity=np.zeros(num_events,dtype=np.int8)
    timestamp=np.zeros(num_events,dtype=np.int64)
    for i in range(num_events):
        start=i*EVENT_SIZE
        event=int.from_bytes(raw_data[start:start+EVENT_SIZE],byteorder="big")
        x[i]=(event>>32)&0xFF
        y[i]=(event>>24)&0xFF
        polarity[i]=(event>>23)&0x01
        timestamp[i]=event&0x7FFFFF
    timestamp=timestamp-timestamp[0]
    max_time=timestamp[-1]
    if max_time==0:
        max_time=1
    time_bins=np.linspace(0,max_time,21)
    event_tensor=np.zeros((20,2,34,34),dtype=np.float32)
    for i in range(num_events):
        t=np.searchsorted(time_bins,timestamp[i],side="right")-1
        if t>=20:
            t=19
        px=x[i]
        py=y[i]
        p=polarity[i]
        if 0<=px<34 and 0<=py<34:
            event_tensor[t,p,py,px]=1
    return event_tensor

print("==============================================")
print("AIS-X2 : SNN TRAINING")
print("==============================================")

files=[]
labels=[]

for digit in range(10):
    digit_files=sorted(glob.glob(os.path.join(DATASET_FOLDER,str(digit),"*.bin")))[:50]
    for file_path in digit_files:
        files.append(file_path)
        labels.append(digit)

print("Training samples:",len(files))
print("Samples per digit: 100")

X=[]
Y=[]

for i,file_path in enumerate(files):
    print("Loading:",i+1,"/",len(files),os.path.basename(file_path))
    X.append(load_event_tensor(file_path))
    Y.append(labels[i])

X=torch.tensor(np.array(X),dtype=torch.float32)
Y=torch.tensor(Y,dtype=torch.long)

print("Input shape:",X.shape)
print("Labels shape:",Y.shape)

dataset=TensorDataset(X,Y)
loader=DataLoader(dataset,batch_size=32,shuffle=True)

model=AISX2SNN()
criterion=nn.CrossEntropyLoss()
optimizer=optim.Adam(model.parameters(),lr=0.001)

epochs=3

for epoch in range(epochs):
    model.train()
    total_loss=0
    correct=0
    total=0
    for batch_X,batch_Y in loader:
        batch_X=batch_X.permute(1,0,2,3,4)
        optimizer.zero_grad()
        functional.reset_net(model)
        output=model(batch_X)
        output_mean=output.mean(dim=0)
        loss=criterion(output_mean,batch_Y)
        loss.backward()
        optimizer.step()
        prediction=torch.argmax(output_mean,dim=1)
        correct+=(prediction==batch_Y).sum().item()
        total+=batch_Y.size(0)
        total_loss+=loss.item()
    accuracy=correct/total*100
    average_loss=total_loss/len(loader)
    print("Epoch:",epoch+1,"Loss:",average_loss,"Accuracy:",accuracy,"%")

torch.save(model.state_dict(),os.path.join(PROJECT_ROOT,"snn_model.pth"))

print("==============================================")
print("SNN TRAINING COMPLETE")
print("Model saved as: snn_model.pth")
print("==============================================")
