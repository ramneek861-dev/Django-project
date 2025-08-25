from django.db import models
from ckeditor.fields import RichTextField



class person(models.Model):
	first_name=models.CharField(max_length=30)
	last_name=models.CharField(max_length=30)


class FAQ(models.Model):
	questions=models.TextField()
	answer=models.TextField()



class Lawer(models.Model):
	Image=models.ImageField(upload_to="data",blank=True)
	Name=models.CharField(max_length=30)
	Contactno=models.CharField(max_length=30)
	Address=models.TextField()
	Experience=models.CharField(max_length=30)
	Info=models.TextField()






class Laws(models.Model):
	Law_category=models.TextField()
	Name=models.TextField()
	Description=models.TextField()



class NGOS(models.Model):
	Name=models.CharField(max_length=30)
	Contactno=models.IntegerField()
	Address=models.CharField(max_length=30)
	Slogen=models.CharField(max_length=30)
	Image=models.ImageField(upload_to="data",blank=True)
	Website=models.CharField(max_length=30)
	Info=models.CharField(max_length=30)
	Emailid=models.EmailField(max_length=30)
	Map=models.CharField(max_length=30)


class Policestations(models.Model):
	Name=models.CharField(max_length=30)
	Contactno=models.CharField(max_length=30)
	Emailid=models.CharField(max_length=100)
	Map=models.ImageField(upload_to="data",blank=True)



class HelpLINENO(models.Model):
	Regional_Office=models.CharField(max_length=1000)
	Name=models.CharField(max_length=100)
	Email=models.CharField(max_length=100)
	Address=models.TextField()
	Telephone_No=models.CharField(max_length=30)
	Mobile_No=models.CharField(max_length=30)


class Myreview(models.Model) :
	Title=models.CharField(max_length=100)
	Message=models.TextField()
	User=models.CharField(max_length=2000)


class userregister(models.Model) :
	Name=models.CharField(max_length=200)
	Password=models.CharField(max_length=300)
	ConfirmPassword=models.CharField(max_length=300)
	Email=models.EmailField()
	MobileNumber=models.CharField(max_length=30, blank=True, null=True)
	# Address=models.CharField(max_length=1000, blank=True, null=True)
	DateOfBirth=models.CharField(max_length=30, blank=True, null=True)
	Gender=models.CharField(max_length=30, blank=True, null=True)
	Image=models.ImageField(upload_to="data", blank=True, null=True)

class editprofile(models.Model):
	Name=models.CharField(max_length=200)

class Alert(models.Model):
	date_published = models.DateField(blank=True, null=True)
	heading = models.CharField(max_length=1000)
	description = RichTextField()
	


class Blog(models.Model):
	Title=models.CharField(max_length=10000)
	Image=models.ImageField(upload_to="data",blank=True)
	des=RichTextField()	