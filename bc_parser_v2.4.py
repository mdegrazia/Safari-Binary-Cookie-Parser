#
#bc_parser.py v2.4
#This program parses the cookies and Google Analytic values from the Mac IOS 
#Cookies.binarycookies file into a TSV format or TLN format
#
#It can also parse carved/incomplete Cookies.binarycookies file.
#It will not process "false negatives" and will pull out as much
#inforamation as it can on carved cookies including those that are incomplete.
#
#
#Many thanks to those who worked hard to discover the binary cookie file format.
#This is based on the binary cookie file structure presented on the blog post:
#www.securitylearn.net/2012/10/27/cookies-binarycookies-reader
#
#The portion of this code that parses the pages, number of cookies, and cookie values borrows
#heavily from the script written by @satishb3 with his permission.
#
#The ability to parse directories, the Google Analytic values and TLN output
#were added/authored by me. 
#
# Copyright (C) 2013 Mari DeGrazia (arizona4n6@gmail.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You can view the GNU General Public License at <http://www.gnu.org/licenses/>
#
# Version History:
# v1.0 2013-8-28
# v2.0 2013-11-01
#	
# Fixed bug when encountering funny domain hash in utma, utmb and utmz value.
#
#V2.0 2013-12-17
# Added ability to parse recover binary cookies that may be incomplete or false positives. If
# the script encounters a false positive it will not process the file. If its a directory full of cookies
# it will move onto the next one. 
#
#v2.03 2016-08-29
#Fixed bug with URL encoded strings
#2017-04-04 updated to fix URL Lib

__author__ = 'arizona4n6@gmail.com (Mari DeGrazia)'
__version__ = '1.2'
__copyright__ = 'Copyright (C) 2013-2016 Mari DeGrazia'
__license__ = 'GNU'


import struct
from StringIO import StringIO
from time import strftime, gmtime
import datetime
import os
import sys
from optparse import OptionParser
import urllib

############################ Functions  ##########################################

def parse_utma(URL,cookie_value):
    
    
    #create dictionary to hold utma values
    utma_value = {}
    utma_value["URL"]=""
    utma_value["Created"]=""
    utma_value["Created_Epoch"]=""
    utma_value["2ndRecentVisit"]=""
    utma_value["MostRecent"]=""
    utma_value["Hit"]=""
    
    utma_values = cookie_value.split('.')
    if len(utma_values) == 0:
        return 0
    else:
                        
               
        utma_value["URL"]=URL
         
        #some utma domain hash values do not want to play nice and have some wonky values that include a period
        #which throws off the count. These also have a colon in them, so look for the colon, if found, advance the count by 1
        
        if ':' in utma_values[1]:
           
            utma_value["Created_Epoch"] = (utma_values[3])
            try:
                utma_value["Created"]=(datetime.datetime.fromtimestamp(int(utma_values[3])).strftime("%Y-%m-%d %H:%M:%S"))
            except:
                utma_value["Created"] = "Error on conversion"
                            
            #second most recent visit
            utma_value["2ndRecentVisit_Epoch"] = (utma_values[4])
            try:
                utma_value["2ndRecentVisit"]=(datetime.datetime.fromtimestamp(int(utma_values[3])).strftime("%Y-%m-%d %H:%M:%S"))
            except:
                utma_value["2ndRecentVisit"]   = "Error on conversion"
                        
            #most recent visit
            utma_value["MostRecent_Epoch"] = (utma_values[5])
            try:
                utma_value["MostRecent"]=(datetime.datetime.fromtimestamp(int(utma_values[5])).strftime("%Y-%m-%d %H:%M:%S"))
            except:
                utma_value["MostRecent"] = "Error on conversion"
                            
            #number of visits
            utma_value["Hit"]=(utma_values[6])
        
        else:
            #cookie create time
        
            utma_value["Created_Epoch"] = (utma_values[2])
            try:
                utma_value["Created"]=(datetime.datetime.fromtimestamp(int(utma_values[2])).strftime("%Y-%m-%d %H:%M:%S"))
            except:
                utma_value["Created"] = "Error on conversion"                
            #second most recent visit
            utma_value["2ndRecentVisit_Epoch"] = (utma_values[3])
            try:
                utma_value["2ndRecentVisit"]=(datetime.datetime.fromtimestamp(int(utma_values[3])).strftime("%Y-%m-%d %H:%M:%S"))
            except:
                utma_value["2ndRecentVisit"]   = "Error on conversion"          
            
            #most recent visit
            utma_value["MostRecent_Epoch"] = (utma_values[4])
            try:
                utma_value["MostRecent"]=(datetime.datetime.fromtimestamp(int(utma_values[4])).strftime("%Y-%m-%d %H:%M:%S"))
            except:
                utma_value["MostRecent"] = "Error on conversion"
                            
            #number of visits
            utma_value["Hit"]=(utma_values[5])
        
        return utma_value
        
def parse_utmb(URL,cookie_value):
    
    #create dictionary to hold utmb values
    utmb_value = {}
    utmb_value["URL"]=""
    utmb_value["PageViews"]=""
    utmb_value["Outbound"]=""
    utmb_value["StartCurrSess"]=""
    utmb_value["StartCurrSess_Epoch"]=""
       
    utmb_values = cookie_value.split('.')
    if len(utmb_values) <= 1:
        return 0
    else:
                        
        utmb_value["URL"]=URL                        
        
        
        #some utmb domain hash values do not want to play nice and have some wonky values that include a period
        #which throws off the count. These also have a colon in them, so look for the colon, if found, advance the count by 1
        
        if ':' in utmb_values[1]:
            #Page View
            utmb_value["PageViews"]=(utmb_values[2])
                
            #outbound links
            utmb_value["Outbound"]=(utmb_values[3])
            #start of current session   
            #if date goes out to milliseconds, get rid of milliseconds
            if len(utmb_values[4])<= 10:
                utmb_value["StartCurrSess_Epoch"] = int(utmb_values[4])           	    
                utmb_value["StartCurrSess"]=(datetime.datetime.fromtimestamp(int(utmb_values[4])).strftime("%Y-%m-%d %H:%M:%S"))
            else:
                utmb_value["StartCurrSess_Epoch"] = (int(utmb_values[4])/1000)
                utmb_value["StartCurrSess"]=(datetime.datetime.fromtimestamp(int(utmb_values[4])/1000).strftime("%Y-%m-%d %H:%M:%S"))
        else:     
            #Page Views
            utmb_value["PageViews"]=(utmb_values[1])
                        
            #outbound links
            utmb_value["Outbound"]=(utmb_values[2])
                    
            #start of current session
            #if date goes out to milliseconds, get rid of milliseconds
            if len(utmb_values[3])<= 10:
                utmb_value["StartCurrSess_Epoch"] = int(utmb_values[3])
                utmb_value["StartCurrSess"]=(datetime.datetime.fromtimestamp(int(utmb_values[3])).strftime("%Y-%m-%d %H:%M:%S"))
            else:
                utmb_value["StartCurrSess_Epoch"] = (int(utmb_values[3])/1000)
                utmb_value["StartCurrSess"]=(datetime.datetime.fromtimestamp(int(utmb_values[3])/1000).strftime("%Y-%m-%d %H:%M:%S"))
    
    
    return utmb_value

def parse_utmz(URL,cookie_value):
    
    #create dictionary to hold utmz values
    utmz_value = {}
    utmz_value["URL"]=""
    utmz_value["LastUpdate"]=""
    utmz_value["LastUpdate_Epoch"]=""
    utmz_value["Source"]=""
    utmz_value["CampName"]=""
    utmz_value["AccesMethod"]=""
    utmz_value["Keyword"]=""
    
    #some cookies are URL encoded, so decode first just in case
       
    try:
        cookie_value = urllib.unquote(cookie_value).decode()
    except:
        print "Error parsing with urlib: " + cookie_value
        
    utmz_values = cookie_value.split('.')
    if len(utmz_values) == 0:
        return 0
    else:
                        
        utmz_value["URL"]=URL
                        
        #Last Update time
        if len(utmz_values[1])<=10:
            utmz_value["LastUpdate_Epoch"] = int(utmz_values[1])
            utmz_value["LastUpdate"]=(datetime.datetime.fromtimestamp(int(utmz_values[1])).strftime("%Y-%m-%d %H:%M:%S"))
        
        #some utmz domain hash values do not want to play nice and have some wonky values that include a period
        #which throws off the count. These also have a colon in them, so look for the colon, if found, advance the count by 1
               
        
        else:
            if ':' in utmz_values[1]:
                utmz_value["LastUpdate_Epoch"] = int(utmz_values[2])
                utmz_value["LastUpdate"]=(datetime.datetime.fromtimestamp(int(utmz_values[2])).strftime("%Y-%m-%d %H:%M:%S"))
            else:    
                try:
                    utmz_value["LastUpdate_Epoch"] = int(utmz_values[1])/1000
                    utmz_value["LastUpdate"]=(datetime.datetime.fromtimestamp(int(utmz_values[1])/1000).strftime("%Y-%m-%d %H:%M:%S"))
                except:
                    print "Error converting time for: " + URL + " " + cookie_value                
        #the utm values are not always in order. thus, we need to located each one in the string and write them out
                            
        #source (utmcsr)
        if "utmcsr" in cookie_value:
            utmcsr = cookie_value.split("utmcsr=")
            
            #partition based on |, take the first section
            try:
                utmcsr_value,temp1,temp2 = utmcsr[1].partition('|')
                utmz_value["Source"]=utmcsr_value
            except:
                print "Error on URL " + URL + " Cookie Value: " + cookie_value
                utmz_value["Source"]='ERROR'
                
            
        else:
            utmz_value["Source"]='utmcsr not found' 
                            
        #campaign
        if "utmccn" in cookie_value:
            utmccn = cookie_value.split("utmccn=")
            utmccn_value,temp1, temp2 = utmccn[1].partition('|')
            utmz_value["CampName"]=utmccn_value
        else:
            utmz_value["CampName"]="utmccn not found" 
                                
        #access method
        if "utmcmd" in cookie_value:
            utmcmd = cookie_value.split("utmcmd=")
            utmcmd_value,temp1, temp2 = utmcmd[1].partition('|')
            utmz_value["AccesMethod"]=utmcmd_value 
        else:
            utmz_value["AccesMethod"]='utmcmd not found' 
                                
        #keywords
        if "utmctr" in cookie_value:
            utmctr = cookie_value.split("utmctr=")
            utmctr_value,temp1, temp2 = utmctr[1].partition('|')
            utmz_value["Keyword"]=utmctr_value.replace('%20', " ")
        else:
            utmz_value["Keyword"]='utmctr not found' 
        
        #path to page on the site of the referring link
        if "utmcct" in cookie_value:
            utmcct = cookie_value.split("utmcct=")
            utmcct_value,temp1, temp2 = utmcct[1].partition('|')
            utmz_value["ReferringPage"]=utmcct_value.replace('%20', " ")
        else:
            utmz_value["ReferringPage"]='utmcct not found'
        
        return utmz_value

#this function takes a file and parses out the cookie and the Google Analytic values. 

def parse_file(in_file,filename):
    
    all_cookies = []
    utmas = []
    utmbs = []
    utmzs =[]


    #make sure the file is a binary plist file
    file_header = in_file.read(4)
    if str(file_header) != 'cook':
        print "Sorry, " + filename + ' is not a Binary Cookie file'
        return False
        
      
    #next is the number of pages in the file; Big Endian
    try:
        number_pages = struct.unpack('>i', in_file.read(4))[0]
    except:
        return False
        
    page_sizes= []
        
    #next is the page size per page; in Big Endian
    try:
        for page in range(number_pages):
            page_sizes.append(struct.unpack('>i', in_file.read(4))[0])
    except:
        return False
    
    #now for each page, use the page size and read the cookie
    pages = []
        
    for i in page_sizes:
        pages.append(in_file.read(i))
        
    for page in pages:
        page = StringIO(page)
            
        #read the page header - 00000100
        page.read(4)
            
        #next, get number of cookies in the page - this is in Little Endian
        try:
            num_cookies=struct.unpack('<i',page.read(4))[0]
        except:
            print "Error getting number of cookies in page"
            break
            
        #after the number of cookies is a four byte integer for each cookies that gives the start offset for the cookie from the beginning of the page
        cookies_offset = []
            
        for j in range(num_cookies):
                cookies_offset.append(struct.unpack('<i',page.read(4))[0]) 
                                                    
        #now that we are done cycling through the offsets, read the page footer, 00000000
        page.read(4)
            
        cookie = ""
         
        #now use the cookies offset, find the cookie from the beginning of the page and read it
        for offset in cookies_offset:
            cookie_value ={}
                        
            page.seek(offset)
                
            #get cookie size
            size_cookie = struct.unpack('<i',page.read(4))[0]
                
            #now read the cookie, 
            
            
           
            cookie = StringIO(page.read(size_cookie))
            
             #what if we have a partial cookie?
            differance = size_cookie - cookie.len
            
            if differance > 4:
                return {'cookies':all_cookies, 'utmas':utmas, 'utmbs':utmbs,'utmzs':utmzs} 
                
                
            
           
            
            
           
                
            cookie.read(4) #unknown value
                
            #now are the cookie flags
            flags = struct.unpack('<i',cookie.read(4))[0]
            cookie_flags =''
                
            if flags == 0:
                cookie_flags = ""
            elif flags == 1:
                cookie_flags = "Secure"
            elif flags == 4:
                cookies_flags = "HTTP Only"
            elif flags == 5:
                cookies_flags = "Secure; Http Only"
                    
            else:
                cookie_flags='unknown'
                    
            cookie.read(4) # unknown
                
            #get the various offsets
            URLOffset = struct.unpack('<i',cookie.read(4))[0]
            nameoffset = struct.unpack('<i',cookie.read(4))[0]
            pathoffset = struct.unpack('<i',cookie.read(4))[0]
            valueoffset = struct.unpack('<i',cookie.read(4))[0]
                
            #read cookie footer, 0000000000000000
            cookie.read(8)
                
            #some of the expiration dates make it blow up on 32bit system
            #dates are in Mac absolute time. Convert to Epoch
            try:       
                exp_date_epoch = struct.unpack('<d',cookie.read(8))[0] + 978307200
                cookie_value['Expiration'] = strftime("%Y-%m-%d %H:%M:%S ", gmtime(exp_date_epoch))[:-1] #[:-1] strips the last space
                cookie_value["Expiration_Epoch"] = exp_date_epoch
            except ValueError:
                cookie_value['Expiration'] = "Error on Date Conversion"
                cookie_value["Expiration_Epoch"] = "Error on Date Conversion"
           
            create_date_epoch = struct.unpack('<d',cookie.read(8))[0]+978307200
            cookie_value['Created_Epoch']= create_date_epoch   
            cookie_value['Created'] = strftime("%Y-%m-%d %H:%M:%S ", gmtime(create_date_epoch))[:-1]
                
                     
            #read URL
            cookie.seek(URLOffset-4)
            cookie_value["URL"]= ""
            u=cookie.read(1)
            try:
                while struct.unpack('<b',u)[0] != 0:
                    cookie_value["URL"] = cookie_value["URL"]+str(u)
                    u=cookie.read(1)
            except: 
                print "Unable to process file"
                return False
            
                    
            #read name
            cookie.seek(nameoffset-4)
            cookie_value["Name"] = ""
            n=cookie.read(1)
            while struct.unpack('<b',n)[0] != 0:
                cookie_value["Name"] = cookie_value["Name"]+str(n)
                n=cookie.read(1)
                
            #read path
            cookie.seek(pathoffset-4)
            cookie_value["Path"] = ""
            p=cookie.read(1)
            while struct.unpack('<b',p)[0] != 0:
                cookie_value["Path"] = cookie_value["Path"]+str(p)
                p=cookie.read(1)   
                
            #read value
            cookie.seek(valueoffset-4)
            cookie_value["Value"] = ""
            va=cookie.read(1)
            while struct.unpack('<b',va)[0] != 0:
                cookie_value["Value"] = cookie_value["Value"]+str(va)
                va=cookie.read(1)     
                
                     
            #add it to the all_cookies array
            all_cookies.append(cookie_value)
            
            
            #lets parse the Google Analytic Values, utma, utmb and utmz
                
            if "utma" in cookie_value["Name"]:                     
                utma_values = parse_utma(cookie_value["URL"],cookie_value["Value"])
            else:
                utma_values = 0
            if "utmb" in cookie_value["Name"]:                     
                utmb_values = parse_utmb(cookie_value["URL"],cookie_value["Value"])
            else:
                utmb_values = 0
                
            if "utmz" in cookie_value["Name"]:                     
                utmz_values = parse_utmz(cookie_value["URL"],cookie_value["Value"])
            else:
                utmz_values = 0      
                    
                          
            #add it to the GA arrays
            if utma_values !=0:
                utmas.append(utma_values)
                
            if utmb_values !=0:
                utmbs.append(utmb_values)
            if utmz_values !=0:
                utmzs.append(utmz_values)    
    
    
    return {'cookies':all_cookies, 'utmas':utmas, 'utmbs':utmbs,'utmzs':utmzs}   


#prints the output in TLN, Timeline format. Takes a dictionary that holds the cookies and the Google Analytic values
def TLN_Print(output, cookies_and_ga):
    for cookie in cookies_and_ga['cookies']:           
            output.write(str(cookie["Created_Epoch"]) + '\t' + "Cookie" + '\t' + options.host + '\t' + options.username + '\t' + "Cookie Created. URL: " + cookie["URL"]  +  " Name: " + cookie["Name"] + " Contents: " + cookie["Value"]+ "\n")
        
    for utma in cookies_and_ga['utmas']:            
        output.write(utma["Created_Epoch"] + '\t' + 'Cookie UTMA' + '\t' + options.host + '\t' + options.username + '\t' 'Cookie Created. URL: ' + utma["URL"] + ' Hits: ' + utma["Hit"]+ '\n')
            
    for utma in cookies_and_ga['utmas']:            
        output.write(str(utma["2ndRecentVisit_Epoch"]) + '\t' + 'Cookie UTMA' + '\t' + options.host + '\t' + options.username +  '\tCookie 2nd Most Recent Visit URL: ' + utma["URL"] + ' Hits: ' + utma["Hit"]+ '\n')
            
    for utma in cookies_and_ga['utmas']:            
        output.write(str(utma["MostRecent_Epoch"]) + '\t' + 'Cookie UTMA' + '\t' + options.host + '\t' + options.username +  '\tCookie Most Recent Visit URL: ' + utma["URL"] + ' Hits: ' + utma["Hit"]+ '\n')
            
            
    for utmb in cookies_and_ga['utmbs']: 
        output.write(str(utmb["StartCurrSess_Epoch"]) + '\t' + "Cookie UTMB\t" + options.host + '\t' + options.username +'\t Start Current Session URL: ' + utmb["URL"] + " Pageviews:" +  utmb["PageViews"]+ " Outbound: " +   utmb["Outbound"] + "\n" )                  
    for utmz in cookies_and_ga['utmzs']:
        output.write(str(utmz["LastUpdate_Epoch"]) + '\t' + "Cookie UTMZ\t" + options.host + '\t' + options.username + '\tCookie Last Upate URL: ' + utmz["URL"]+ " Source: " + utmz["Source"]+ " Campaign Name: "  +   utmz["CampName"]+ " Access Method: "
                       +    utmz["AccesMethod"]+ " Keyword: "  +    utmz["Keyword"]+ " Referring Page: " + utmz["ReferringPage"] + "\n")
                    
#prints out the cookie information "normally". Creates one file for the cookie information, and three files for the Google Analytic values
def Normal_Print(output, cookies_and_ga):
   
    for cookie in cookies_and_ga['cookies']:
        output.write(options.infile + "\t" +cookie["URL"] + '\t' + cookie["Name"] + '\t' + cookie["Created"] + '\t' + cookie["Expiration"] + '\t' + cookie["Path"] + '\t' + cookie["Value"] + '\n')                       
        
    for utma in cookies_and_ga['utmas']:            
        utma_output.write(options.infile + "\t" + utma["URL"] + "\t" + utma["Created"]+ "\t" +  utma["2ndRecentVisit"]+ "\t"  +  utma["MostRecent"]+ "\t" +   utma["Hit"]+ "\n")
        
    for utmb in cookies_and_ga['utmbs']: 
        utmb_output.write(options.infile + "\t" + utmb["URL"] + "\t" +  utmb["PageViews"]+ "\t" +   utmb["Outbound"]+ "\t" +    utmb["StartCurrSess"]+ "\n" )                  

    for utmz in cookies_and_ga['utmzs']:
        utmz_output.write(options.infile + "\t" + utmz["URL"]+ "\t"  +  utmz["LastUpdate"]+ "\t"  +  utmz["Source"]+ "\t"  +   utmz["CampName"]+ "\t"  +    utmz["AccesMethod"]+ "\t"  +    utmz["Keyword"]+ "\t" + utmz["ReferringPage"] + "\n")
                       

############################ Main  ##########################################

usage = "\n\nThis program parses the cookies and Google Analytic values from the Mac IOS Cookies.binarycookies file into a CSV format or TLN format.\
 The script will parse either a file (-f) or a directory recursively (-d) of binary cookies.\
The script will parse the cookies, as well as any utma,utmb and utmz Google Analytic value contained in the cookies.\n\n\
There will be four files created. One file for the cookies, and one file for each of the Google Analytic values. If the Timeline format (-t) \
is selected there will be one file created in TLN format with both cookies and Google Analytic values.\n\n\
Examples:\n\
-f Cookies.binarycookies -o cookies.tsv\n\
-d /home/sanforensics/allcookies -o cookies.tsv\n\
-f Cookies.binarycookies -o cookies.tsv -t -H MariPC -u Mari"

parser = OptionParser(usage=usage)

parser.add_option("-f", "--file", dest = "infile", help = "binary cookies file", metavar = "Cookies.binarycookies")
parser.add_option("-o", "--output", dest = "outfile", help = "output to a tsv file", metavar = "output.tsv")
parser.add_option("-d", "--dir", dest = "directory", help = "process all files in directory", metavar = "/home/sansforensics/allcookies")

#TLN timeline options
parser.add_option("-t", "--tln", action ="store_true", dest="TLN",help = "Optional. TimeLine format")
parser.add_option("-H", "--Host", dest = "host", help = "Optional. Host name, i.e. Computer Name", metavar = "MariPC")
parser.add_option("-u", "--user", dest = "username", help = "Optional. Username, i.e. Profile where cookie was located", metavar = "Mari")

(options,args)=parser.parse_args()


#no arugments given by user,exit
if len(sys.argv) == 1:
    parser.print_help()
    exit(0)


#there has to be either a file or a directory selected and the name of the output file - if not exit
if (options.infile == None and options.directory == None) or options.outfile == None:
    parser.print_help()
    print "Filename or Directory or output file not given"
    exit(0)
   

#check to make sure that both the infile and directoy were not selected together
if options.directory != None and options.infile != None:
    parser.print_help()
    print "Please choose either -f or -d, not both"
    exit(0)

       
#if host or username not given, set blank
if options.host == None:
    options.host = ""
if options.username == None:
    options.username = ""
 
cookie_count = 0

#get the output files ready
output = open(options.outfile, 'w')
filename,temp,ext = options.outfile.rpartition(".")


 
#if the timeline option is set write the TLN header, otherwise, write the normal cookie and GA headers
if options.TLN == True:
    output.write("Time\tSource\tHost\tUsername\tDescription\tNotes\n")

else:
    output.write('Source\tURL\tName\tCreated\tExpires\tPath\tContents\t\n')
       
    #Google Analytic output files
    
    utma_output = open(filename + "__utma." + ext, 'w')
    utma_output.write('Source\tURL\tCreated\t2nd Most Recent Visit\tMost Recent\tHits\n')
        
        
    utmb_output = open(filename + "__utmb." + ext, 'w')
    utmb_output.write('Source\tURL\tPage Views\tOutbound\tStart Current Session\n')
        
    utmz_output = open(filename + "__utmz." + ext,  'w')
    utmz_output.write('Source\tURL\tLast Update\tSource\tCampaign Name\tAccess Method\tKeyword\tReferring Page\n')

#if only one file was selected, process that file
if options.infile != None:
    try:
        f = open(options.infile, "rb")
    except IOError as e:
        print 'File Not Found :' + options.infile
        exit(0)
            
    cookies_and_ga = parse_file(f,options.infile)
    if cookies_and_ga == 0:
        print "incomplete file"
        exit(0) 
   
    #if TLN is set, print out in timeline format
    if options.TLN == True and cookies_and_ga != False:
        TLN_Print(output, cookies_and_ga)    
    
    #if TLN output is not set, print out cookies and GA normally
    if options.TLN == None and cookies_and_ga != False:
        Normal_Print(output, cookies_and_ga)
       
    
#if a directory was selected, process all files in that directory        
if options.directory != None:
    
    #check to see if the directory exists, if not, silly user.. go find the right directory!
    if os.path.isdir( options.directory) == False:
        print ("Could not locate directory. Please check path and try again")
        exit (0)
    #crap, now we need to check to see if the path is a windows or linux path
    
    if '\\' in options.directory:
        seperator = "\\"
    if '/' in options.directory:
        seperator = "/"

    #loop through each file
    for subdir, dirs, files in os.walk(options.directory):
        for filename in files:
            options.infile = options.directory+ "/" + filename    
        #try to open the files, if not there bail out
            try:
                f = open(options.infile, "rb")
            except IOError as e:
                print 'File Not Found :' + options.infile
                exit(0)
                    
            print "Processing " + filename
            cookies_and_ga = parse_file(f,filename)    
           
            #if TLN is set, print out in timeline format
            if options.TLN == True and cookies_and_ga != False:
                TLN_Print(output, cookies_and_ga)
            
            #if TLN output is not set, print out cookies and GA normally
            if options.TLN == None and cookies_and_ga != False:
                               
                Normal_Print(output, cookies_and_ga)    
       

#be polite and close out the files
output.close()
if options.TLN == None:
    utma_output.close
    utmb_output.close
    utmz_output.close

#booyeah - we're done! 
                
