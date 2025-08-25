from django.shortcuts import render,redirect
from cyberapp.models import Laws
from cyberapp.models import Myreview,userregister
from cyberapp.models import  HelpLINENO
from cyberapp.models import *
from django.conf import settings
from django.core.mail import send_mail
import requests 
import whois
from django.shortcuts import render 
import base64
import datetime 
from datetime import date
from newsapi.newsapi_client import NewsApiClient
from urllib.parse import urlparse
import pandas as pd




# Create your views here.


def contact(request):
	return render(request,'contact us.html')

def home(request):
	review =  Myreview.objects.all().order_by('-id')[:3]

	return render(request,'home.html' ,{'data':review})

def sidebar(request):
	return render(request,'sidebar.html')


def changepass(request):
	if not request.session.has_key('Email'):
		return redirect('/sigin')
	
	if request.method=="POST":
		o=request.POST.get('op')
		n=request.POST.get('np')
		c=request.POST.get('cp')
		if n==c:
			user=userregister.objects.get(Email=request.session['Email'])
			p=user.Password
			if o==p:
				user.Password=n
				user.ConfirmPassword=n
				user.save()
				msg="successfully changes"
				return render(request,'changePassword.html',{'msg':msg})
			else:
				msg="Invalid current Password"
				return render(request,'changePassword.html',{'msg':msg})
		else:
			msg="pass and ConfirmPassword does not match"
			return render(request,'changePassword.html',{'msg':msg})
	else:
		return render(request,'changePassword.html')




def forgot(request):
	if request.method=='POST':
		em=request.POST.get('em')
		user=userregister.objects.filter(Email=em)
		if(len(user)>0):
			pw=user[0].Password
			subject="Password"
			Message="Welcome to Intelliguard Cyber your password is" +pw
			email_from=settings.EMAIL_HOST_USER
			recipient_list=[em,]
			send_mail(subject,Message,email_from,recipient_list)
			rest="your password sent to your respective Email Account.please check"
			return render(request,'forgotpassword.html',{'msg':rest})
		else:
			res="This email id is not registered"
			return render(request,'forgotpassword.html',{'msg':rest})
	else:
		return render(request,'forgotpassword.html')

		

def sign(request):
	if request.method=="POST":
		e=request.POST.get('em')
		p=request.POST.get('ps')
		user=userregister.objects.filter(Email=e, Password=p)
		k=len(user)
		if k>0:
			request.session['Email']=e
			return redirect('/dashboard')

		else:
			return render(request,'signin.html', {'msg':"Invalid Candidate"})
	else:
		return render(request,'signin.html')


	


def signup(request):
	if request.method=="POST":
		n=request.POST.get('nm')
		e=request.POST.get('em')
		p=request.POST.get('ps')
		c=request.POST.get('cps')
		if userregister.objects.filter(Email=e).exists():
			msg="Email Id is already exists"
			return render(request,'signup.html',{'msg':msg})
		else:
			if p==c:
				x=userregister()
				x.Name=request.POST.get('nm')
				x.Email=request.POST.get('em')
				x.Password=request.POST.get('ps')
				x.ConfirmPassword=request.POST.get('ps')
				x.save()
				msg="You are successfully Register! "
				return render(request,'signup.html',{'msg':msg})
			else:
				msg="Password and Confirm-Passwors is not same"
				return render(request,'signup.html',{'msg':msg})

	else:
		return render(request,'signup.html')





def base(request):
	return render(request,'base.html')

def urlscan(request):
	if request.method=="POST":
		url=request.POST.get('url')
		url_bytes = url.encode('utf-8')
		# Encode URL bytes to Base64 without padding
		url_base64 = base64.b64encode(url_bytes).decode('utf-8').rstrip("=")

		print("Base64 encoded domain:", url_base64)
		url = "https://www.virustotal.com/api/v3/urls/"+url_base64

		headers = {
		    "accept": "application/json",
		    "x-apikey": "68fa79f6b4f59f33ad6b6a481f5bb131ff760244485bc380fe11aeb7a138cd8b"
		}

		response = requests.get(url, headers=headers)

		print(response.text)
		r = response.json()
		k=r['data']['attributes']['last_analysis_results']
		last_analysis_stats=r['data']['attributes']['last_analysis_stats']
		return render(request,'urlscanresult.html',{'k':k, 'url':url, 'last_analysis_stats':last_analysis_stats,})


		# pass
	else: 
		return render(request,'urlscan.html')



def ip(request):
	if request.method=="POST":
		ip=request.POST.get('ip')

		url = "https://www.virustotal.com/api/v3/ip_addresses/103.120.179.177"
		headers = {
		"accept": "application/json",
		"x-apikey": "68fa79f6b4f59f33ad6b6a481f5bb131ff760244485bc380fe11aeb7a138cd8b"
		}
		response = requests.get(url, headers=headers)
		print(response.text)
		m = response.json()
		n=m['data']['attributes']['last_analysis_results']
		continent=m['data']['attributes']['continent']
		country=m['data']['attributes']['country']
		last_analysis_stats=m['data']['attributes']['last_analysis_stats']
		last_analysis_date=m['data']['attributes']['last_analysis_date']
		return render(request,'ipresult.html',{'n':n,'ip':ip, 'continent':continent, 'country':country, 'last_analysis_stats':last_analysis_stats,
			'last_analysis_date':last_analysis_date,})
	else: 
		return render(request,'ip.html')



def domain(request):
	if request.method=="POST":
		domain=request.POST.get('domain')
		
		# code for domain report
		url = "https://www.virustotal.com/api/v3/domains/ssssccw.edu.in"
		headers = {
		"accept": "application/json",
		"x-apikey": "68fa79f6b4f59f33ad6b6a481f5bb131ff760244485bc380fe11aeb7a138cd8b"
		}
		response = requests.get(url, headers=headers)
		t=response.json()
		d=t['data']['attributes']['last_analysis_results']
		creation_date=t['data']['attributes']['creation_date']
		last_analysis_stats=t['data']['attributes']['last_analysis_stats']

		return render(request,'domainreport.html',{'d':d,'creation_date':creation_date,'last_analysis_stats':last_analysis_stats,})
	else: 
		return render(request,'domain.html')



def whois(request):
	if request.method=="POST":
		d=request.POST.get('whois')
		# code for domain report
		import whois

		# Use the whois.whois() function to query WHOIS information for the domain
		w = whois.whois('gndu.ac.in')

		# The rest of your code to handle the WHOIS information
		if isinstance(w.expiration_date, list):
		    expiration_date = w.expiration_date[0]
		else:
		    expiration_date = w.expiration_date
		print(expiration_date)  # dates converted to datetime object
		print(w.text)  # the content downloaded from whois server
		print(w)  # print values of all found attributes

		k=w.text
		t=k.split('\n')
		return render(request,'whoisresult.html',{'t':t})
	else: 
		return render(request,'whois.html')
	
def handle_uploaded_file(f,name):
	destination = open(name, 'wb+')
	for chunk in f.chunks():
		destination.write(chunk)
		destination.close()

def filescan(request):
	if request.method=='POST':
	    f = request.FILES['file'] 
	    handle_uploaded_file(f,f.name)
	    print("filescan")
	    import os
	    import time
	    import json
	    import virustotal3.core
	    API_KEY='68fa79f6b4f59f33ad6b6a481f5bb131ff760244485bc380fe11aeb7a138cd8b'
	    vt = virustotal3.core.Files('68fa79f6b4f59f33ad6b6a481f5bb131ff760244485bc380fe11aeb7a138cd8b')
	    response = vt.upload(f.name)
	    analysis_id = response['data']['id']
	    print('Analysis ID: {}'.format(analysis_id))
	    results = virustotal3.core.get_analysis(API_KEY, analysis_id)
	    status = results['data']['attributes']['status']
	    print('Waiting for results...')
	    while 'completed' not in status:
	    	results = virustotal3.core.get_analysis(API_KEY, analysis_id)
	    	status = results['data']['attributes']['status']
	    	print('Current status: {}'.format(status))
	    	time.sleep(10)
	    results = virustotal3.core.get_analysis(API_KEY, analysis_id)
	    k=json.dumps(results, indent=4, sort_keys=True)
	    print(k[0])
	    k=json.dumps(results, indent=4, sort_keys=True)
	    import json
	    s=json.loads(k)
	    res=s["data"]["attributes"]["results"]
	    stats=s["data"]["attributes"]["stats"]
	    import pandas as pd
	    df = pd.DataFrame(res)
	    df=df.transpose()
	    df=df.reset_index()
	    k1=['Sophos','StopBadware','Lumu','Netcraft','NotMining','AutoShun','Cyan']
	    print(k1)
	    df.columns
	    df.rename(columns = {'index':'antivirus'}, inplace = True)
	    df =df[(df.antivirus !='Sophos') & (df.antivirus !='Netcraft') & (df.antivirus !='StopBadware') & (df.antivirus !='Lumu') & (df.antivirus !='NotMining') & (df.antivirus !='AutoShun') & (df.antivirus !='Cyan')   ]
	    l=[]
	    for j,i in zip(df.iloc[:,1],df.iloc[:,0]):
	    	print([i,j])
	    	l.append([i,j])
	    return render(request,"filescanresult.html",{'l':l,'stats':stats,})
	else:
		return render(request,'filescan.html')
		   
    	

def quickscan(request):
	if request.method=='POST':
		target=request.POST.get('url')
		print(target)
		import socket
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		t_IP = socket.gethostbyname('gndu.ac.in')
		print("Starting scan on host: ", t_IP)
		port=[20,21,23,25,53,443,110,135,137,138,139,1433,1434]
		result=[]
		for i in port:
			l=[]
			try:
				s.connect((t_IP, i))
				l.append(i,'port open')
			except:
				l.append([i,'port Closed'])
				result.append(l)
		return render(request,'quickscanresult.html',{'result':result})
	else:
		return render(request,'quickscan.html')



def porthost(request):
	if request.method=='POST':
		target=request.POST.get('url')
		port=request.POST.get('portno')
		print(target)
		print(port)
		import socket
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		t_IP = socket.gethostbyname('ssssccw.edu.in')
		print("Starting scan on host: ", t_IP)
		ports = [20, 21, 23, 25, 53, 443, 110, 135, 137, 138, 139, 1433, 1434]
		results = []
		for port in ports:
			try:
				s.connect((t_IP, port))
				results.append((port, True))
				s.close()
			except:
				results.append((port, False))
		return render(request,'porthostresult.html',{'results':results,'target':target})
	else:
		return render(request,'porthost.html') 		
	



def portno(request):
		if request.method=='POST':
			target=request.POST.get('')
			port=request.POST.get('portno')
			print(target)
			print(port)
			import socket 
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			t_IP = socket.gethostbyname('ssssccw.edu.in')
			print("Starting scan on host: ", t_IP)
			port=[20,21,23,25,53,443,110,135,137,138,139,1433,1434]
			result=[]
			for i in port:
				l=[]
				try:
					s.connect((t_IP, i))
					l.append(i,'port open')
				except:
					l.append([i,'port Closed'])
					result.append(l)
			return render(request,'portnoresult.html',{'result':result,})
		else:
			return render(request,'portno.html')



def extract_website(link):
	parsed_url = urlparse(link)
	if parsed_url.netloc:
		return parsed_url.netloc
	else:
		return parsed_url.path.split('/')[0]


def phishing(request):
	if request.method=='POST':
		link=request.POST.get('link')
		website = extract_website(link)
		print(website)  # Output: www.example.com\
		result='Not Phishing'
		df = pd.read_csv('phishing_site_urls.csv',engine="python")
		dff=df['URL']
		df.columns=df.iloc[0,:]
		df=df.iloc[1:,:]
		for x in dff:
			if website in x :
				result='Phishing website'
				break
		print("Result",result)
		return render(request,'phishingresult.html',{'result':result})
	else:
		return render(request,'phishing.html')




def banner(request):
	if request.method=='POST':
		target=request.POST.get('target_host')
		
		target_host = request.POST.get('target_host')
		target_port = 80
		print("target_host",target_host)
		# Perform banner grabbing for technology detection
		result=banner_grabbing(target_host, target_port)
		print(result)
		
		return render(request,'bannerresult.html',{'result':result,})
	else:
		return render(request,'banner.html')

import socket
def banner_grabbing(target_host, target_port):
    try:
        # Create a socket object
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       
        # Set a timeout for the connection
        client_socket.settimeout(5)

        # Connect to the target host and port
        client_socket.connect((target_host, target_port))

        # Send a request to the target service
        client_socket.send(b'GET / HTTP/1.1\r\nHost: ' + target_host.encode() + b'\r\n\r\n')

        # Receive the banner response
        banner = client_socket.recv(4096)

        # Decode the response
        banner_str = banner.decode()

        # Split the response into lines
        banner_lines = banner_str.split('\n')

        # Extract specific headers for technology detection
        server_header = next((line for line in banner_lines if line.lower().startswith('server')), None)
        x_powered_by_header = next((line for line in banner_lines if line.lower().startswith('x-powered-by')), None)
        other_headers = [line for line in banner_lines if ':' in line and line.lower() not in [server_header, x_powered_by_header]]
        result=[]
        # Print the extracted headers
        print("[+] Technology detected for {}:{}".format(target_host, target_port))
        result.append("[+] Technology detected for {}:{}".format(target_host, target_port))
        if server_header:
            print("Server: {}".format(server_header.strip()))
            result.append("[+] Technology detected for {}:{}".format(target_host, target_port))
        if x_powered_by_header:
            print("X-Powered-By: {}".format(x_powered_by_header.strip()))
            result.append("[+] Technology detected for {}:{}".format(target_host, target_port))
        if other_headers:
            print("Other Headers:")
            result.append("[+] Technology detected for {}:{}".format(target_host, target_port))
            for header in other_headers:
                print(header.strip())
                result.append(header.strip())
        print("result is ",result)      
        return result

    except Exception as e:
        print("[-] Error: {}".format(e))

    finally:
        # Close the socket connection
        client_socket.close()
	





def AboutUs(request):
	return render(request,'AboutUs.html')

def faqs(request):
	return render(request,'faqs.html')


def helpline(request):
	helpline =  HelpLINENO.objects.all()
	return render(request,'All Helpline.html',{'data':helpline})

def laws(request):
	law=Laws.objects.all()#modelsname.

	return render(request,'All Laws.html',{'data':law})	



def policestation(request):
    policestations = Policestations.objects.all()  # Assuming Policestation is the correct model name.

    return render(request, 'All Policestations.html', {'data': policestations})



def services(request):
	return render(request,'services.html')


def review(request):
	user=userregister.objects.get(Email=request.session['email'])
	if request.method=="POST":
		print("yes")
		x=Myreview()
		x.Title=request.POST.get('nm')
		x.Message=request.POST.get('msg')
		x.User=user.Name + " ," +user.Email
		x.save()
		return render(request,'review.html',{'msg':"successfully add your review"})
	else:
		return render(request,'review.html')

def userprofile(request):
	if not request.session.has_key('Email'):
		return redirect('/sigin')
	
	x=userregister.objects.get(Email=request.session['Email'])
	if request.method=="POST":
		print("yes")
		x.Image=request.FILES['file']
		x.save()
		return render(request,'userprofile.html',{'user':x,'msg':'success'})
	else:
		return render(request,'userprofile.html',{'user':x})
	



def editprofile(request):
	if not request.session.has_key('Email'):
		return redirect('/sigin')
	
	user=userregister.objects.get(Email=request.session['Email'])
	if request.method=="POST":
		user.Name=request.POST.get('name')
		user.MobileNumber=request.POST.get('MobileNumber')
		
		user.DateOfBirth=request.POST.get('DateOfBirth')
		user.Gender=request.POST.get('gender')
		user.save()
		return redirect('/userprofile')
	else:
		return render(request,'editprofile.html',{'user':user})

	
def logout(request):
	if not request.session.has_key('Email'):
		return redirect('/sigin')
	del request.session['Email']
	return redirect('/sigin')



def newsapi(request):
	newsapi=NewsApiClient(api_key='9977d45a2873403b88d670b0fca4daa1')
	json_data = newsapi.get_everything(q='cybersecurity',language='en', from_param=str(date.today() - datetime.timedelta(days=29)),to= str(date.today()),page_size=18,page=1,sort_by='relevancy')
	k=json_data['articles']

	return render (request,'newsapi.html',{'k' : k})



def databr(request):
	from cybernews.cybernews import CyberNews
	news = CyberNews() # Instance is created
	k=news.get_news("dataBreach")
	return render(request,'databr.html',{'k':k})



def cyberattack(request):
	from cybernews.cybernews import CyberNews
	news = CyberNews() # Instance is created
	j=news.get_news("cyberAttack")
	return render(request,'cyberattack.html',{'j':j})

def malware(request):
	from cybernews.cybernews import CyberNews
	news = CyberNews() # Instance is created
	n=news.get_news("malware")
	return render(request,'malware.html',{'n':n})

def secure(request):
	from cybernews.cybernews import CyberNews
	news = CyberNews() # Instance is created
	s=news.get_news("security")
	return render(request,'secure.html',{'s':s})

def cloud(request):
	from cybernews.cybernews import CyberNews
	news = CyberNews() # Instance is created
	m=news.get_news("cloud")
	return render(request,'cloud.html',{'m':m})

def tech(request):
	from cybernews.cybernews import CyberNews
	news = CyberNews() # Instance is created
	t=news.get_news("tech")
	return render(request,'tech.html',{'t':t})


def iot(request):
	from cybernews.cybernews import CyberNews
	news = CyberNews() # Instance is created
	i=news.get_news("iot")
	return render(request,'iot.html',{'i':i})


def bigdata(request):
	from cybernews.cybernews import CyberNews
	news = CyberNews() # Instance is created
	b=news.get_news("bigData")
	return render(request,'bigdata.html',{'b':b})

def business(request):
	from cybernews.cybernews import CyberNews
	news = CyberNews() # Instance is created
	a=news.get_news("business")
	return render(request,'business.html',{'a':a})

def research(request):
	from cybernews.cybernews import CyberNews
	news = CyberNews() # Instance is created
	r=news.get_news("research")
	return render(request,'research.html',{'r':r})


def dashboard(request):
	alerts =  Alert.objects.all()
	return render(request, 'dashboard.html', {'alerts': alerts})	


def detailalert(request,id):
	alerts =  Alert.objects.get(id=id)
	return render(request,'detailalert.html',{'alert':alerts})


def password_security_view(request):
    # Placeholder view for password security topic
    return render(request, 'password_security.html')

def malware_prevention_view(request):
    # Placeholder view for malware prevention topic
    return render(request, 'malware_prevention.html')

def social_engineering_view(request):
    # Placeholder view for social engineering topic
    return render(request, 'social_engineering.html')

def data_protection_view(request):
    # Placeholder view for data protection topic
    return render(request, 'data_protection.html')

def secure_web_browsing_view(request):
    # Placeholder view for secure web browsing topic
    return render(request, 'secure_web_browsing.html')

def mobile_security_view(request):
    # Placeholder view for mobile security topic
    return render(request, 'mobile_security.html')


def security(request):
	return render(request,'Security.html')



def blog(request):
	blog =  Blog.objects.all()
	return render(request,'Blog.html',{'data':blog})



def detailblog(request,id):
	blog =  Blog.objects.get(id=id)
	return render(request,'detailblog.html',{'i':blog})	


def help(request):
	return render(request,'Help&Support.html')	
