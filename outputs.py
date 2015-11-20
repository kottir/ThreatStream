import csv
import linecache

'''
functions within the class:
csvoutfile
csvoutfile1
unique_result
final_result

The main objective of the OutputTypes class is to print out the results in a csv format.
It is to be extended for an output on the screen.

name_file and blob1 have been passed to the object in the threat_api.py file.
They hold the output file name and the raw json blob respectively.

'''
class OutputTypes(object):

	def __init__(self,name_file,blob1):
		'''
		The class contructor. 

		Arguments: 
		name_file= the name of the output file.
		blob1= the raw json blob.

		Doesn't return anything.

		'''

		self.blob=blob1
		self.file_name=name_file

	def final_result(self,list_,strng,number_total):
		'''
		Appends the final result which is the summary into the csv file.

		Arguments:
		list_= the list which contains the values to be used for determining the summary.
		strng= specifies the field for which a summary is being constructed.
		number_total= the total number of entries for the specific ip.

		Doesn't return anything.
		set function is used to determine the unique values from the list, list_.

		Variables:
		z is the writer object of the csv module for the file pointer f.
		xx holds each unique value in the specific list.
		co keeps the count for each xx value.

		'''
		f=open(self.file_name,"a")
		z=csv.writer(f,quoting=QUOTE_MINIMAL,lineterminator="\n")
		z.writerow([""])
		z.writerow(["SUMMARY"])
		z.writerow(["",""])
		z.writerow([strng,"count"])
		#print list_
		if len(set(list_))==1:
			z.writerow([list_[0]+"\t",number_total])
		else:
			for i in set(list_):
				xx=str(i)
				co=0
				for j in range(0,len(list_)):
					if xx==list_[j]:
						xx=xx+"\t"
						co+=1
				z.writerow([xx,co])
		z.writerow([""])
		z.writerow(["total_count",number_total])
		f.close()

	def unique_result(self,total_len,line_strt,file_ends):
		'''

		Funtion to determine the various values for each field that will be used to contruct the summary.
		Uses linecache module to read the required lines off the file created so far.
		The cache is cleared after the lists have been determined.

		Arguments:
		total_len= the total number of entries for the specific IP.
		line_strt= the line where the program must begin reading the file.
		file_ends= the line number upto which the reading should continue. Hence file_ends+1 is included in the range.

		The function doesn't return anything.
		It calls the method final_result for each list constructed.

		Variables:
		list_severity= the list holding the values of the severity field.
		list_detail= list to hold the various values of the detail field.
		list_itype= holds the itype values.

		'''
		list_severity=[]
		list_itype=[]
		list_detail=[]
		for i in range(line_strt,file_ends+1):
			r=[]
			l= linecache.getline(self.file_name,i)
			l.rstrip()
			r.split(',',1)
			if r[0]=="severity":
				list_severity.append(r[1])
			elif r[0]=="itype":
				list_itype.append(r[1])
			elif r[0]=="detail":
				list_detail.append(r[1])
		linecache.clearcache()

		self.final_result(list_severity,"severity",total_len)
		self.final_result(list_itype,"itype",total_len)
		self.final_result(list_detail,"detail",total_len)


	def csvoutfile1(self):
		'''

		This function is for parsing through the json blob and writing the results into the csv file.
		It is for every IP after the first one.
		Here the results are appended rather than written.

		Arguments:
		No arguments are taken.

		This function doesn't return anything.
		It calls the unique_result for determining the summary of the values it just wrote into the file.
		Varies from the csvoutfile method at 2 places- first, it appends and second, the arguments sent to the unique_result method are different.

		Variables:
		line_start is counted to determine where this method exactly starts writing.
		blob_len= the length of the raw json blob.
		file_end is counted to determine exactly upto which line the method wrote.

		'''
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
		#print line_start+1, file_end
		self.unique_result(blob_len,(line_start+2),(file_end+1))

	def csvoutfile(self):
		'''

		This function is for writing the initial results into the file.
		Will be exclusively used for the first IP given.

		Arguments:
		None taken.

		Doesn't return anythin.
		Calls the unique_result method to determine the summary of the data it just wrote into the file.
		This is the only method that opens the output file with the "wb" tag.

		Variables:
		line_start here is zero as it is the function that will initiate the writing into the output file.
		file_end is counted to determine exactly upto which line the method wrote.
		blob_len= the length of the raw json blob.

		'''
		f=open(self.file_name,"wb")
		c=csv.writer(f,quoting=csv.QUOTE_MINIMAL,lineterminator="\n")
		#cc=0
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


