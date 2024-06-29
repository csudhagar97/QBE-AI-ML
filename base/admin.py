from django.contrib import admin
from .models import Account, FileHandle, Prescription
# Register your models here.
admin.site.register(Account)
admin.site.register(FileHandle)
admin.site.register(Prescription)