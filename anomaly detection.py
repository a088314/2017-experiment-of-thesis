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

# 讀取security log 檔案並剖析每一筆event，萃取出重要資訊並用"#"符號將每個重要資訊接在一起
def transform_Sec():
	# Security logs
	Stree=et.ElementTree(file='.\\data\\security.xml')
	root=Stree.getroot()
	result=''  #result字串儲存最後要寫入csv檔的文字內容
	for child in root: 
		# Security elementTree
		# 開始遍歷每一筆event，並依照不同的event萃取出不同的欄位資訊
		for grandchild in child[0]:
			# 將EventID及system time萃取出來存於EventId, Time 變數
			if 'EventID' in grandchild.tag:
				# print (grandchild.text)
				EventID=grandchild.text
			if 'SystemTime' in grandchild.attrib:
				# print(grandchild.get('SystemTime'))
				Time=grandchild.get('SystemTime').replace('T',' ')[:grandchild.get('SystemTime').index('.')]
		# 每一筆的event轉換成為自訂格式的字串，儲存於Activity變數，每個迴圈更新一次
		Activity=''
		# 4648 Run as 

		# 以下萃取出每一筆event ID的方式都一樣，以ID 4648為例說明
		if EventID=='4648':
			# child[1]代表的是一筆event 下面的data tag裡的所有tag
			# 將需要萃取出來的資訊使用"grandchild.get("name")"=atrribute 的方式取出該attrib的值
			for grandchild in child[1]:
				# 以下的每
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
	# 將result回傳回去，因為還多了一個"\n"，所以slicing [:-1]
	return result[:-1]

def transform_Sys():
	import re
	# 建立Windows 時間格式，以分辨出該格是否是儲存時間
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
		# 因為有些update會在更新的軟體/元件之後以括號附註版本號
		# 若是附上版本號的話，則同一軟體的更新會被視為不同事件
		# 因此我們只要擷取更新軟體就好，將括號裡的資訊拿掉
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
		# 6008
		# EventID 6008是電腦意外關機的事件，而該事件的記錄時間不是真正意外發生的時間
		# 而是意外發生之後的下一次開機，因此必需要修改Time 變數，將意外發生的時間
		# 取代系統記錄的時間，而我們抓取欄位資料的方式即是以正規表示法判斷該tag的值是否為Windows時間格式
		# 如果是的話，再判斷發生時間為上午或下午，將時間轉換為24小時的表示方式，最後將之寫回Time變數
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

# 將轉換過的log data 儲存於transformed log.txt
def Write_Transform_Log_into_file(result):
	# write transformed log data
	with open('transformed log.txt','wt') as fout:
		fout.write(result)

# 這裡只是做一些統計，將每一種事件發生幾次，顯示在瑩幕上
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

plt.rcParams['font.sans-serif']=['SimHei'] #plt用以正常顯示中文 (但還是會失敗QQ), 好像這個套件只能支援英文
with open('transformed log.txt', 'rt') as fin:
    Alldata=fin.read().split('\n')
DistinctAct=[] #記錄所有使用者發生的distinct 行為
TotalAct=[]    #記錄使用者發生的行為 (依序記錄)
TotalTime=[]   #記錄使用者發生行為的時間 (依序記錄)

# 讀取transformed log.txt ，將上述三個變數內容填寫完畢
for data in Alldata:
    act=data.split(',')[1].strip()
    time=data.split(',')[0]
    if act not in DistinctAct:
        DistinctAct.append(act)
    TotalAct.append(act)
    TotalTime.append(time)

# 印出相關資訊 (num: 資料筆數，以及共有幾種不同的行為)
dim=len(TotalAct)
num=len(Alldata)
print(num)
print(len(DistinctAct))

# 使用python pandas套件的資料儲存結構-pandas來儲存資料
df=pd.read_csv('transformed log.csv', names=['Datetime','Activity'])
# print(df.dtypes)
# 執行一些相關設定，將編號以事件發生時間取代，並修改datetime欄位格式為datetime格式
df['Datetime']=pd.to_datetime(df['Datetime'])
df['Activity']=df['Activity'].astype(str)
df['Datetime']=df['Datetime']+timedelta(hours=8)
df.index=df['Datetime']
# print(df.dtypes)
# print(df.head())

# 計算使用者行為矩陣，亦即論文第四章第四節的內容
# 我們要建一個大矩陣，每一欄為一種行為
# 若有發生該行為則記錄1，無則記錄0
for i in DistinctAct:
	ser_list=[]
	for j in TotalAct: 
		if i == j:
			ser_list.append(1)
		else:
			ser_list.append(0)
	series=pd.Series(ser_list, index=TotalAct).astype(int)
	df[DistinctAct.index(i)]=ser_list

# 已經不需要activity, and Datetime columns了，將之移除
df.drop(['Activity','Datetime'], axis=1, inplace=True)

# 利用dataframe裡的resample function, 可以直接以一個小時為單位，記錄
df_HS = df.resample('H').sum()
df_HS = df_HS.fillna(0.0)
df_HS.to_csv('Bunithour.csv')

# 利用df裡的apply function，將資料正規化 (計算zscore)
d_scored=df_HS.apply(zscore)
d_scored.to_csv('unithour.csv')

stage2_data=d_scored

# 由pdist創建distance matrix
Y=pdist(stage2_data,'euclidean')
Y=squareform(Y)
# 將k設為資料數的開根號
K=math.floor(len(stage2_data)**(1/2))
print(K)

# 開始計算每一個資料點與其最近k個資料點的距離之平均
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

# normal
# 計算所有資料點與其最近k個資料點之平均的平均及標準差
avg=sum(Each_Average)/len(Each_Average)
print("Average of average distance", avg)
std=statistics.stdev(Each_Average)
print("Standard deviation of average distance", std)
print('-----------------')
print("The number of exceed 3 sigma", len([i for i in Each_Average if i > avg+3.3*std]))
print(Each_Average[-3:])


# 把所有的維度都印出來
# write 維度
tmp=''
for i in DistinctAct:
	tmp+=i+', '
with open('columns','wt') as fout:
	fout.write(tmp)


# plt 開始畫圖
plt.plot(range(0,len(Each_Average)), Each_Average)
plt.plot(range(0,len(Each_Average)), [avg+3.3*std]*len(Each_Average),'r')
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