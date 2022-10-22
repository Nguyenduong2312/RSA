from email import message
from email.policy import default
from django.db import models
from django.contrib.auth.models import User
# from django.utils.translation import gettext as _
from django.contrib import messages
from django import forms
import os
DEFAULT_PASSWORD = 'password'

class Account_info(models.Model):
    user = models.OneToOneField(User, null=True, blank=True, on_delete=models.CASCADE)
    name = models.CharField(max_length=200, null=True)
    email = models.EmailField(unique=True)
    birth = models.DateField(null=True)
    address = models.CharField(max_length=200, null=True, blank=True)
    phone = models.CharField(max_length=200, null=True, blank=True) #sua lai dang number
    first_login = models.BooleanField(default=True)
    private_key = models.BinaryField(null=True, blank=True)
    public_key = models.BinaryField(null=True, blank=True)
    public_key1 = models.CharField(max_length=200, null=True, blank=True)
    def __str__(self):
        return self.name
class Encrypt(models.Model): 
    sender_email = models.EmailField(blank=True)
    receiver_email = models.EmailField()
    file = models.FileField(default='name.txt', max_length=254) 
    en_file = models.FileField(default='name.txt', max_length=254) 
    @property
    def filename(self):
        return os.path.basename(self.document.name)
    def __str__(self):
        return self.receiver_email
    