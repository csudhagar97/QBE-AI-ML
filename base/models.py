from django.db import models
from django.contrib.auth.models import User


class Account(models.Model):
    USER_TYPE_CHOICES = (('normal', 'normal'),('medical_stuff', 'medical_stuff'),('doctor', 'doctor'))
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    user_type = models.CharField(max_length=255, default='normal', choices=USER_TYPE_CHOICES)
    first_name = models.CharField(max_length=255, default='None')
    last_name = models.CharField(max_length=255, default='None')
    age = models.IntegerField()
    blood_group = models.CharField(max_length=255, default='None')
    gender = models.CharField(max_length=255, default='None')
    email  =models.CharField(max_length=255,default ='None')
    medical_note = models.CharField(max_length=2000, default='None')
    secret_key = models.CharField(max_length = 50, default='expectropatronum')
    def __str__(self):
        return f'{self.user.username} - {self.first_name} - {self.last_name}'

from django.db import models
from django.contrib.auth.models import User

from django.db import models

class FileHandle(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    filename = models.CharField(max_length=255)
    file = models.FileField(upload_to='files/')
    doctor = models.ForeignKey(User, related_name='doctor_files', on_delete=models.CASCADE)
    user_reconstructed_key = models.CharField(max_length=100)  # Add reconstructed key for user
    encrypted_content = models.BinaryField(default=b'')  # Default value set to empty bytes
    content_name = models.CharField(max_length=255)
    def __str__(self):
        return self.filename




#class Prescription(models.Model):
  #  user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='prescriptions')
  #  file = models.ForeignKey('FileHandle', on_delete=models.CASCADE, related_name='prescriptions')
   # details = models.TextField()

 #   def __str__(self):
  #      return f'Prescription for {self.user.username}'

   # def __str__(self):
     #   return f'{self.user.username}'
from django.db import models
from django.contrib.auth.models import User

class Prescription(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    details = models.TextField()
    doctor1 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='prescriptions')
    prescription_file = models.FileField(upload_to='prescriptions/', blank=True)
    
    
    def __str__(self):
        return 'Prescription for {}'.format(self.user.username)
