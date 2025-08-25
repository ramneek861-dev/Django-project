"""
URL configuration for Intelliguard_cyber project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from cyberapp import views


from django.conf import settings
from django.contrib.staticfiles.urls import static
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

urlpatterns = [
    path("admin/", admin.site.urls),
    path('contact',views.contact,name="contact"),
    path('foo',views.forgot,name="foo"),
    path('sigin',views.sign, name="sigin"),
    path('sign',views.signup, name="sign"),
    path('bs',views.base),
    path('abu',views.AboutUs, name="abu"),
    path('faq',views.faqs, name="faq"),
    path('helpline',views.helpline, name="helpline"),
    path('law',views.laws, name="law"),
    path('serv',views.services, name="serv"),
    path('policestation', views.policestation, name="policestation"),
    path('review',views.review,name="review"),
    path('sidebar',views.sidebar),
    path('changepass',views.changepass, name="changepass"),
    path('',views.home, name="home"),
    path('userprofile',views.userprofile,name="userprofile"),
    path('editprofile',views.editprofile, name="editprofile"),
    path('logout', views.logout, name="logout"),
    path('urlscan', views.urlscan, name="urlscan"),
    path('filescan', views.filescan, name="filescan"),
    path('quickscan', views.quickscan, name="quickscan"),
    path('porthost', views.porthost, name="porthost"),
    path('phishing', views.phishing, name="phishing"),
    path('portno', views.portno, name="portno"),
    path('domain', views.domain, name="domain"),
    path('whois', views.whois, name="whois"),
    path('ip', views.ip, name="ip"),
    path('newsapi', views.newsapi, name="newsapi"),
    path('databr',views.databr, name="databr"),
    path('cyberattack',views.cyberattack, name="cyberattack"),
    path('malware',views.malware, name="malware"),
    path('secure',views.secure, name="secure"),
    path('cloud',views.cloud, name="cloud"),
    path('tech',views.tech, name="tech"),
    path('iot',views.iot, name="iot"),
    path('bigdata',views.bigdata, name="bigdata"),
    path('business',views.business, name="business"),
    path('research',views.research, name="research"),
    path('banner',views.banner, name="banner"),
    path('dashboard',views.dashboard, name="dashboard"),
    path('detailalert/<int:id>',views.detailalert, name="detailalert"),
    path('password-security/', views.password_security_view, name='password_security'),
    path('malware-prevention/', views.malware_prevention_view, name='malware_prevention'),
    path('social-engineering/', views.social_engineering_view, name='social_engineering'),
    path('data-protection/', views.data_protection_view, name='data_protection'),
    path('secure-web-browsing/', views.secure_web_browsing_view, name='secure_web_browsing'),
    path('mobile-security/', views.mobile_security_view, name='mobile_security'),
    path('security',views.security, name="security"),
    path('blog',views.blog, name="blog"),
    path('detailblog/<int:id>',views.detailblog, name="detailblog"),
    path('help',views.help, name="help"),
    


]


urlpatterns+=staticfiles_urlpatterns()
urlpatterns+=static(settings.MEDIA_URL,document_root=settings.MEDIA_ROOT)