from .models import Prescription

class PrescriptionForm(forms.ModelForm):
    class Meta:
        model = Prescription
        fields = ['user', 'details']

@login_required
def create_prescription(request):
    
    if request.method == 'POST':
        user_id = request.POST.get('user_id')  
        details = request.POST.get('prescription')  
        user = User.objects.get(pk=user_id)
        prescription = Prescription.objects.create(user=user, details=details)
        prescription.save()
        return redirect('view_prescriptions')  # Redirect to view prescriptions page
    else:
        # Render prescription creation form
        return render(request, 'send_prescription.html')
from django.urls import reverse
from django.http import HttpResponseRedirect   
def test_user_dropdown(request):
    users = User.objects.all()
    if request.method == 'POST':
        selected_user_id = request.POST.get('user_id')
        return HttpResponseRedirect(reverse('send_prescriptions', args=[selected_user_id]))
    return render(request, 'test_dropdown.html', {'users': users})


@login_required
def send_prescriptions(request):
    if request.method == 'POST':
        # Retrieve the selected user ID and prescription details from the form
        user_id = request.POST.get('user_id')
        prescription_details = request.POST.get('prescription')
        
        # Retrieve the selected user object
        selected_user = User.objects.get(pk=user_id)
        
        # Create a Prescription object with the selected user and prescription details
        Prescription.objects.create(user=selected_user, details=prescription_details)
        
        # Redirect to view prescriptions page
        return redirect('view_prescriptions')
    else:
        # If it's a GET request, fetch all users for the dropdown
        users = User.objects.all()
        
        # Render the send_prescription.html template with the users
        return render(request, 'send_prescription.html', {'users': users})







@login_required
def view_prescriptions(request):
    
    
    return render(request,'view_prescriptions.html')

from django.shortcuts import render
from django.contrib.auth.models import User

def test_user_dropdown(request):
    users = User.objects.all()
    return render(request, 'test_dropdown.html', {'users': users})
