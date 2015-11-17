The original ThreatStream API wouldn’t produce an output due to a problem in it’s output function.
This project started out as a revision to that API, where the output function was modified, thus making it display few fields within the json blob obtained. 

The code was then modified to display the results that I felt were important for my work- itype, detail, threatscore, status, severity.
It was then modified to give the output in a csv format, which would be a better resource. 

The project then evolved to include cidr ranges given in the format x.y. ( i.e., for example, 190.34.). The url has been modified such that only the IP’s starting with 190.34. (as per our example) and having an active status will be retrieved. By viewing the included query string in the url, you can identify how the server will be made to pass on, only the active records. 

A summary to the end of the report was desired, so the summary has been appended at the end of the cvs file.

The project has been running smooth so far. But then the code has been modified to take in multiple IP’s as the target, and give the results in the same csv file. Here, the code seems to get complicated due to the various restrictions imposed by the csv module. It can be made much smoother using the “openpyxl” library which would give us an excel workbook and we could use one sheet per target.

The code at present takes in both IP’s and CIDR’s and a single csv file as the output. It will be extended to include multiple csv files if the user so desires. 

Openpyxl is highly recommended, the code for which I will be uploading soon. 
