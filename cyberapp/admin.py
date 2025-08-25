from django.contrib import admin
from cyberapp.models import person
from cyberapp.models import FAQ
from cyberapp.models import Lawer
from cyberapp.models import Laws
from cyberapp.models import NGOS
from cyberapp.models import Policestations
from cyberapp.models import HelpLINENO
from cyberapp.models import Myreview
from cyberapp.models import userregister
from cyberapp.models import Alert
from cyberapp.models import Blog




# Register your models here.
admin.site.register(person)
admin.site.register(FAQ)
admin.site.register(Lawer)
admin.site.register(Laws)
admin.site.register(NGOS)
admin.site.register(Policestations)
admin.site.register(HelpLINENO)
admin.site.register(Myreview)
admin.site.register(userregister)
admin.site.register(Alert)
admin.site.register(Blog)
