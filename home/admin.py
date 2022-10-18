from django.contrib import admin

# Register your models here.
from .models import *

admin.site.enable_nav_sidebar = False
admin.site.register(Account_info)

admin.site.register(File_doc)
