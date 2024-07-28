from django.db import models
from django.contrib.auth.models import User

class Account(models.Model):
    USER_TYPE_CHOICES = (
        ('normal', 'normal'),
        ('medical_staff', 'medical_staff'),
        ('doctor', 'doctor')
    )
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    user_type = models.CharField(max_length=255, default='normal', choices=USER_TYPE_CHOICES)
    first_name = models.CharField(max_length=255, default='None')
    last_name = models.CharField(max_length=255, default='None')
    age = models.IntegerField()
    blood_group = models.CharField(max_length=255, default='None')
    gender = models.CharField(max_length=255, default='None')
    email = models.CharField(max_length=255, default='None')
    medical_note = models.CharField(max_length=2000, default='None')
    secret_key = models.CharField(max_length=50, default='expectropatronum')
    username = models.CharField(max_length=255, default='None')
    approved_doctors = models.ManyToManyField(User, related_name='approved_doctors', blank=True)

    def __str__(self):
        return f'{self.user.username} - {self.first_name} - {self.last_name}'

class FileHandle(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    filename = models.CharField(max_length=255)
    file = models.FileField(upload_to='files/')
    doctor = models.ForeignKey(User, related_name='doctor_files', on_delete=models.CASCADE)
    user_reconstructed_key = models.CharField(max_length=100)
    encrypted_content = models.BinaryField(default=b'')
    content_name = models.CharField(max_length=255)

    def __str__(self):
        return self.filename

class Prescription(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    details = models.TextField()
    doctor1 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='prescriptions')
    prescription_file = models.FileField(upload_to='prescriptions/', blank=True)

    def __str__(self):
        return 'Prescription for {}'.format(self.user.username)

class Approval(models.Model):
    file = models.ForeignKey(FileHandle, on_delete=models.CASCADE, related_name='approvals', db_column='file_id')
    file_name = models.CharField(max_length=255, blank=True)
    approver = models.ForeignKey(User, on_delete=models.CASCADE, db_column='approver_id')
    approved = models.BooleanField(default=False, db_column='approved')
    approval_time = models.DateTimeField(null=True, blank=True, db_column='approval_time')
    requester = models.ForeignKey(User, related_name='approval_requests', on_delete=models.CASCADE, db_column='requester_id')
    requester_type = models.CharField(max_length=10, default='doctor')  # Default to 'doctor'

    def save(self, *args, **kwargs):
        if not self.file_name and self.file:
            self.file_name = self.file.filename
        super().save(*args, **kwargs)

from django.db import models
from django.contrib.auth.models import User

class MedicalRecord(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='medical_records')
    file = models.FileField(upload_to='medical_records/')
    description = models.TextField(blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.user.username} - {self.file.name}"

