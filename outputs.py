import csv
import linecache

class OutputTypes(object):

	def __init__(self,name_file,blob1):
		self.blob=blob1
		self.file_name=name_file

	def final_result(self,list_,strng,file_ptr,number_total):
		total_count=number_total
		z=file_ptr
		z.writerow(["",""])
		z.writerow([strng,"count"])
		print list_
		if len(set(list_))==1:
			z.writerow([list_[1],total_count])
		else:
			for i in set(list_):
				xx=str(i)
				co=0
				for j in range(0,len(list_)):
					if xx==list_[j]:
						co+=1
				z.writerow([xx,co])
		return

	def unique_result(self,total_len,line_strt,file_ends):
		list_severity=[]
		list_itype=[]
		list_detail=[]
		for i in range(line_strt,file_ends+1):
			r=[]
			l= linecache.getline(self.file_name,i)
			r.split(',',1)
			if r[0]=="severity":
				list_severity.append(r[1])
			elif r[0]=="itype":
				list_itype.append(r[1])
			elif r[0]=="detail":
				list_detail.append(r[1])

		f=open(self.file_name,"a")
		c=csv.writer(f,quoting=csv.QUOTE_MINIMAL,lineterminator="\n")
		c.writerow(["",""])
		c.writerow(["SUMMARY"])
		self.final_result(list_severity,"severity",c,total_len)
		self.final_result(list_itype,"itype",c,total_len)
		self.final_result(list_detail,"detail",c,total_len)
		c.writerow(["",""])
		c.writerow(["total_count",total_len])
		f.close()

	def csvoutfile1(self):
		line_start=0
		with open(self.file_name) as f1:
			for l in f1:
				line_start+=1
		f=open(self.file_name,"a")
		c=csv.writer(f,quoting=csv.QUOTE_MINIMAL,lineterminator="\n")
		blob_len= len(self.blob)
		c.writerow(["",""])
		for y in range(0,blob_len):
			r=self.blob[y]
			for i,j in r.items():
				if i=="status" or i=="itype" or i=="ip":
					c.writerow([i,j])
				elif i=="threatscore":
					j=str(j)+"\t"
					c.writerow([i,j])
				if i=="meta":
					ss=j
					for g,h in ss.items():
						c.writerow([g,h])
						if g=="detail":
							c.writerow(["",""])
		f.close()
		file_end=0
		with open(self.file_name) as f2:
			for ll in f2:
				file_end+=1
		print line_start+1, file_end
		self.unique_result(blob_len,line_start+1,file_end)

	def csvoutfile(self):
		f=open(self.file_name,"wb")
		c=csv.writer(f,quoting=csv.QUOTE_MINIMAL,lineterminator="\n")
		cc=0
		blob_len=len(self.blob)
		for y in range(0,blob_len):
			r=self.blob[y]
			for i,j in r.itmes():
				if i=="status" or i=="threatscore" or i=="itype" or i=="ip":
					c.writerow([i,j])
				if i=="meta":
					ss=j
					for g,h in ss.items():
						c.writerow([g,h])
						if g=="detail":
							c.writerow(["",""])
		f.close()
		file_end=0
		line_start=1
		with open(self.file_name) as f1:
			for l in f1:
				file_end+=1
		print file_end
		self.unique_result(blob_len,line_start,file_end)