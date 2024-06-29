from django import forms
from django.contrib.auth.models import User
from .models import Prescription

class PrescriptionForm(forms.ModelForm):
    class Meta:
        model = Prescription
        fields = ['user', 'details']