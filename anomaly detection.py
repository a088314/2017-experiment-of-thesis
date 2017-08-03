#coding:utf-8
import pandas as pd
from datetime import datetime, timedelta
import numpy as np
from scipy.spatial.distance import pdist, squareform
from scipy.stats import zscore
import math
import statistics
import matplotlib.pyplot as plt
import xml.etree.ElementTree as et

def transform_Sec():
	# Security logs
	Stree=et.ElementTree(file='.\\data\\security.xml')
	root=Stree.getroot()
	result=''
	for child in root: 
		# System elementTree
		for grandchild in child[0]:
			if 'EventID' in grandchild.tag:
				# print (grandchild.text)
				EventID=grandchild.text
			if 'SystemTime' in grandchild.attrib:
				# print(grandchild.get('SystemTime'))
				Time=grandchild.get('SystemTime').replace('T',' ')[:grandchild.get('SystemTime').index('.')]
		# Data elementTree
		Activity=''
		# 4648 Run as 
		if EventID=='4648':
			for grandchild in child[1]:
				# print(grandchild.tag, grandchild.attrib)
				# if 'Name' in grandchild.attrib:
				if grandchild.get('Name')=='SubjectUserName':
					Activity+='#'+grandchild.text
				# if 'Name' in grandchild.attrib:
				if grandchild.get('Name')=='TargetUserName':
					Activity+='#'+grandchild.text
				if grandchild.get('Name')=='TargetServerName':
					Activity+='#'+grandchild.text

		# 4634 Logoff
		if EventID=='4634':
			for grandchild in child[1]:
				if grandchild.get('Name')=='TargetUserName':
					Activity+='#'+grandchild.text
				if grandchild.get('Name')=='LogonType':
					Activity+='#'+grandchild.text

		# 4647 User Initial logoff
		if EventID=='4647':
			for grandchild in child[1]:
				if grandchild.get('Name')=='TargetUserName':
					Activity+='#'+grandchild.text

		# 4624 Logon
		if EventID=='4624':
			for grandchild in child[1]:
				if grandchild.get('Name')=='TargetUserName':
					Activity+='#'+grandchild.text
				if grandchild.get('Name')=='LogonType':
					Activity+='#'+grandchild.text

		# 4672 Special privileges assigned to new logon
		if EventID=='4672':
			for grandchild in child[1]:
				if grandchild.get('Name')=='SubjectUserName':
					Activity+='#'+grandchild.text
				if grandchild.get('Name')=='PrivilegeList':
					Activity+='#'+grandchild.text.replace('\t','').replace('\n','@')
		# 4907 Auditing settings on object were changed
		if EventID=='4907':
			pass
			# for grandchild in child[1]:
			# 	if grandchild.get('Name')=='SubjectUserName':
			# 		Activity+='#'+grandchild.text
			# 	if grandchild.get('Name')=='ObjectName':
			# 		Activity+='#'+grandchild.text
		# 4776 logon failed
		if EventID=='4776':
			for grandchild in child[1]:
				if grandchild.get('Name')=='TargetUserName':
					Activity+='#'+grandchild.text
		# 4724 change account's password
		if EventID=='4724':
			for grandchild in child[1]:
				if grandchild.get('Name')=='TargetUserName':
					Activity+='#'+grandchild.text
		# 4731 create group
		if EventID=='4731':
			for grandchild in child[1]:
				if grandchild.get('Name')=='TargetUserName':
					Activity+='#'+grandchild.text
		# 4732 add user into a group
		if EventID=='4732':
			for grandchild in child[1]:
				if grandchild.get('Name')=='TargetUserName':
					Activity+='#'+grandchild.text
		# 4722 create user account
		if EventID=='4722':
			for grandchild in child[1]:
				if grandchild.get('Name')=='TargetUserName':
					Activity+='#'+grandchild.text
		# 4719 system audit policy was change

		# 4725 delete user account
		if EventID=='4732':
			for grandchild in child[1]:
				if grandchild.get('Name')=='TargetUserName':
					Activity+='#'+grandchild.text
		# 1102 log clear
		result+=Time+', '+EventID+Activity+'\n'

	print('the number of security logs is:', len(result.split('\n'))-1)
	return result[:-1]

def transform_Sys():
	import re
	srcDay='\d\d\d\d-\d{1,2}-\d{1,2}'
	srcTime='\S\S \d\d:\d\d:\d\d'
	Stree=et.ElementTree(file='.\\data\\system.xml')
	root=Stree.getroot()
	result=''
	for child in root: 
		# System elementTree
		for grandchild in child[0]:
			if 'EventID' in grandchild.tag:
				# print (grandchild.text)
				EventID=grandchild.text
			if 'Name' in grandchild.attrib:
				Source=grandchild.get('Name')
				# print(Source)
			if 'SystemTime' in grandchild.attrib:
				# print(grandchild.get('SystemTime'))
				Time=grandchild.get('SystemTime').replace('T',' ')[:grandchild.get('SystemTime').index('.')]
		Activity='default'
		# 41
		if EventID=='41' and Source=='Microsoft-Windows-Kernel-Power':
			Activity=''
		# 1
		if EventID=='1' and Source=='Microsoft-Windows-Kernel-General':
			Activity=''
		# 13
		if EventID=='13' and Source=='Microsoft-Windows-Kernel-General':
			Activity=''	
		# 12
		if EventID=='12' and Source=='Microsoft-Windows-Kernel-General':
			# for grandchild in child[1]:
			# 	if grandchild.get('Name')=='StartTime':
			# 		Activity='#'+grandchild.text
			Activity=''
		# 7040 
		if EventID=='7040' and Source=='Service Control Manager':
			for grandchild in child[1]:
				if grandchild.get('Name')=='param1':
					Activity='#'+grandchild.text
		# 7040 
		if EventID=='7000' and Source=='Service Control Manager':
			for grandchild in child[1]:
				if grandchild.get('Name')=='param1':
					Activity='#'+grandchild.text
		# 7045 
		if EventID=='7040' and Source=='Service Control Manager':
			for grandchild in child[1]:
				if grandchild.get('Name')=='ServiceName':
					Activity='#'+grandchild.text
		# 6005
		if EventID=='6005' and Source=='EventLog':
			Activity=''
		# 6006
		if EventID=='6006' and Source=='EventLog':
			Activity=''
		# 6009
		if EventID=='6009' and Source=='EventLog':
			Activity=''
		# 19
		if EventID=='19' and Source=='Microsoft-Windows-WindowsUpdateClient':
			for grandchild in child[1]:
				if grandchild.get('Name')=='updateTitle':
					temp=grandchild.text
					if '(' in temp and ')' in temp:
						Activity='#'+temp[:temp.index('(')]+temp[temp.index(')')+2:]
					else:
						Activity='#'+temp
		# 20
		if EventID=='20' and Source=='Microsoft-Windows-WindowsUpdateClient':
			for grandchild in child[1]:
				if grandchild.get('Name')=='updateTitle':
					temp=grandchild.text
					if '(' in temp and ')' in temp:
						Activity='#'+temp[:temp.index('(')]+temp[temp.index(')')+2:]
					else:
						Activity='#'+temp
		# 6009
		if EventID=='6008' and Source=='EventLog':
			time, day = '', ''
			for grandchild in child[1]:
				tmp=grandchild.text
				if tmp:
					tmp=tmp.replace('\u200e','').replace('/','-')
					if re.search(srcDay, tmp):
						tmp=tmp.split('-')
						day=tmp[0].zfill(2)+'-'+tmp[1].zfill(2)+'-'+tmp[2].zfill(2)
					if re.search(srcTime, grandchild.text):
						if grandchild.text[:2]=='上午':
							hour=int(grandchild.text[3:5]) if int(grandchild.text[3:5])<12 else 0
						elif grandchild.text[:2]=='下午':
							hour=int(grandchild.text[3:5])+12 if int(grandchild.text[3:5])<12 else int(grandchild.text[3:5])
						time=str(hour).zfill(2)+grandchild.text[5:]
			Time=day+' '+time
			Activity=''
		# 104 
		if EventID=='104' and Source=='Microsoft-Windows-Eventlog':
			Activity=''
		if Activity!='default':
			result+=Time+', '+EventID+Activity+'\n'	
	print('the number of system logs is:',len(result.split('\n'))-1)
	return result[:-1]

def Write_Transform_Log_into_file(result):
	# write transformed log data
	with open('transformed log.txt','wt') as fout:
		fout.write(result)

def CalculateAllKindsOfEvents(res):
	from collections import Counter
	res=res.split('\n')
	mylist=[]
	for data in res:
		mylist.append(data.split(',')[1].strip())
	c=Counter(mylist)
	print(len(c))
	for k, v in c.items():
		print(k+', '+str(v))

SecRes=transform_Sec()
SysRes=transform_Sys()
res=SecRes + '\n' + SysRes
Write_Transform_Log_into_file(res)
CalculateAllKindsOfEvents(res)

# ----- log format transform end -----# 

plt.rcParams['font.sans-serif']=['SimHei'] #plt用以正常顯示中文
with open('transformed log.txt', 'rt') as fin:
    Alldata=fin.read().split('\n')
DistinctAct=[]
TotalAct=[]
TotalTime=[]
for data in Alldata:
    act=data.split(',')[1].strip()
    time=data.split(',')[0]
    if act not in DistinctAct:
        DistinctAct.append(act)
    TotalAct.append(act)
    TotalTime.append(time)


dim=len(TotalAct)
num=len(Alldata)
print(num)
print(len(DistinctAct))

df=pd.read_csv('transformed log.csv', names=['Datetime','Activity'])
# print(df.dtypes)
df['Datetime']=pd.to_datetime(df['Datetime'])
df['Activity']=df['Activity'].astype(str)
df['Datetime']=df['Datetime']+timedelta(hours=8)
df.index=df['Datetime']
# print(df.dtypes)
# print(df.head())

for i in DistinctAct:
	ser_list=[]
	for j in TotalAct: 
		if i == j:
			ser_list.append(1)
		else:
			ser_list.append(0)
	series=pd.Series(ser_list, index=TotalAct).astype(int)
	df[DistinctAct.index(i)]=ser_list

df.drop(['Activity','Datetime'], axis=1, inplace=True)
# print(df.head())
# print(df.dtypes)
df_HS = df.resample('H').sum()
df_HS = df_HS.fillna(0.0)
df_HS.to_csv('Bunithour.csv')

d_scored=df_HS.apply(zscore)
d_scored.to_csv('unithour.csv')


# print(d_scored.index)
First_stage_anomaly_number=0
anomaly_interval=[]
for n, i in enumerate(d_scored.index):
	tmp=all(j < 5 for j in d_scored.loc[i])
	if not tmp:
		First_stage_anomaly_number+=1
		anomaly_interval.append(n)
print(First_stage_anomaly_number)
print('false alarm rate=', First_stage_anomaly_number/len(d_scored))
print(len(anomaly_interval))


# drop these time interval that may be anomaly?

# stage2_data=d_scored.drop(d_scored.index[anomaly_interval])
stage2_data=d_scored

# print(len(stage2_data))
Y=pdist(stage2_data,'euclidean')
Y=squareform(Y)
K=math.floor(len(stage2_data)**(1/2))
print(K)
# print(Y)

Each_Average=[]
for i in Y:
	mylist=sorted(i.tolist())[:K]
	Each_Average.append(sum(mylist)/len(mylist))

# write Each_Average to a file
tmp=''
for i in range(len(Each_Average)):
	tmp+=str(Each_Average[i])+'\n'
with open('Each Average.txt','wt') as fout:
	fout.write(tmp)

# print(sorted(Y[0].tolist()))
# print(len(Each_Average))
# print("Average of average distance", sum(Each_Average)/(len(Each_Average)-Each_Average.count(0)))




# normal
avg=sum(Each_Average)/len(Each_Average)
print("Average of average distance", avg)
std=statistics.stdev(Each_Average)
print("Standard deviation of average distance", std)
print('-----------------')
print("The number of exceed 3 sigma", len([i for i in Each_Average if i > avg+3.3*std]))
print(Each_Average[-3:])



# write 維度
tmp=''
for i in DistinctAct:
	tmp+=i+', '
with open('columns','wt') as fout:
	fout.write(tmp)


# plt
plt.plot(range(0,len(Each_Average)), Each_Average)
plt.plot(range(0,len(Each_Average)), [avg+3.3*std]*len(Each_Average),'r')
# plt.text(30, 100, r'$\mu={0:.2f},\ \sigma={1:.2f},\ K={2}$'.format(avg, std,K))
plt.text(15,95, r'$\mu={0:.2f}$'.format(avg))
plt.text(15,90, r'$\sigma={0:.2f}$'.format(std))
plt.text(15,85,'# of anomlay = {}'.format(len([i for i in Each_Average if i > avg+3.3*std])),color='g')

plt.annotate('Injected\nanomaly', color='blue', xy=(1460,80), xytext=(1250, 65),
            arrowprops=dict(facecolor='blue', shrink=10),
            )


plt.annotate('Anomaly treshold = {0:.2f}'.format(avg+3.3*std), xy=(1200, avg+3.3*std), xytext=(900, 95),
            arrowprops=dict(facecolor='red', shrink=1.5),
            )
plt.xlabel('Time interval')
plt.ylabel('Average distance')
plt.title(u'每個時間區間與其最近K個鄰居的平均距離')
plt.show()