import os
import glob
import numpy as np
import torch
from snn_model import AISX2SNN

PROJECT_ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_FOLDER=os.path.join(PROJECT_ROOT,"data","Test")
MODEL_PATH=os.path.join(PROJECT_ROOT,"snn_model.pth")

def load_event_tensor(file_path):
    with open(file_path,"rb") as f:
        raw_data=f.read()
    num_events=len(raw_data)//5
    x=np.zeros(num_events,dtype=np.int16)
    y=np.zeros(num_events,dtype=np.int16)
    polarity=np.zeros(num_events,dtype=np.int8)
    timestamp=np.zeros(num_events,dtype=np.int64)
    for i in range(num_events):
        event=int.from_bytes(raw_data[i*5:i*5+5],byteorder="big")
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

files=[]
labels=[]

for digit in range(10):
    digit_files=sorted(glob.glob(os.path.join(DATASET_FOLDER,str(digit),"*.bin")))[:10]
    for file_path in digit_files:
        files.append(file_path)
        labels.append(digit)

print("Test samples:",len(files))

X=[]
Y=[]

for i,file_path in enumerate(files):
    print("Loading:",i+1,"/",len(files))
    X.append(load_event_tensor(file_path))
    Y.append(labels[i])

X=torch.tensor(np.array(X),dtype=torch.float32)
Y=torch.tensor(Y,dtype=torch.long)
X=X.permute(1,0,2,3,4)

model=AISX2SNN()
model.load_state_dict(torch.load(MODEL_PATH,weights_only=True))
model.eval()

with torch.no_grad():
    output=model(X)
    output_mean=output.mean(dim=0)
    prediction=torch.argmax(output_mean,dim=1)

accuracy=(prediction==Y).float().mean().item()*100

print("==============================================")
print("AIS-X2 : SNN TESTING")
print("==============================================")
print("Test samples:",len(Y))
print("Correct predictions:",(prediction==Y).sum().item())
print("Accuracy:",accuracy,"%")
print("==============================================")
