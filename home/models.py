from email import message
from email.policy import default
from django.db import models
from django.contrib.auth.models import User
# from django.utils.translation import gettext as _
from django.contrib import messages
from django import forms

DEFAULT_PASSWORD = 'password'

class Account_info(models.Model):
    user = models.OneToOneField(User, null=True, blank=True, on_delete=models.CASCADE)
    name = models.CharField(max_length=200, null=True)
    email = models.EmailField(unique=True)
    birth = models.DateField(null=True)
    address = models.CharField(max_length=200, null=True, blank=True)
    phone = models.CharField(max_length=200, null=True, blank=True) #sua lai dang number
    first_login = models.BooleanField(default=True)
    def __str__(self):
        return self.name
class File_doc(models.Model):
    name = models.CharField(max_length=200, null=True)
    field_name = models.FileField(default='name.txt', max_length=254) 
    def __str__(self):
        return self.name
    