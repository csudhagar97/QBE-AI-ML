from itertools import combinations
import secrets
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect
from django.core.files.base import ContentFile
from django.http import FileResponse
from django.core.files.storage import default_storage

from attribute_telemed import settings
from .models import FileHandle, Account
import random
from cryptography.fernet import Fernet
import io
#from secretsharing import SecretSharer
import string
from django import forms
import base64
from django.core.mail import send_mail
from django.core.mail import EmailMessage
from attribute_telemed.settings import EMAIL_HOST_USER
from cryptography.fernet import Fernet
from django.core.files.base import ContentFile

def home(request):
    print(request.user)
    return render(request, 'home.html')

def user_register(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        password2 = request.POST['password2']
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email =request.POST['email']
        age = request.POST['age']
        blood_groups = request.POST['blood_groups']
        gender = request.POST['gender']
        medical_note = request.POST['medical_note']
        role = request.POST['role']
        if password == password2:
            user = User.objects.create_user(username=username, password=password)
            if role in ['medical_stuff', 'doctor']:
                user_type = role
            else:
                user_type = 'normal'

            #user_type = 'normal'
            #if role in ['medical_stuff', 'doctor']:
                #user_type = role
            account_ins = Account.objects.create(user=user, user_type=user_type,first_name=first_name, last_name=last_name,email=email,age=age, blood_group=blood_groups, gender=gender, medical_note=medical_note, secret_key=''.join([random.choice('abcdefghijklmnopqrstuvwxyz') for i in range(30)]))
            user.save()
            account_ins.save()
            return redirect('home')
    return render(request, 'user_register.html')
def generate_secret_key():
    """Generates a random key of specified length."""
    return Fernet.generate_key()
def split_secret_key(secret_key):
  """Splits a string into 3 keys with overlap, padding if necessary."""
  padding_length = (3 - len(secret_key) % 3) % 3  # Calculate padding length
  padded_key = secret_key + '0' * padding_length  # Pad the key with '0'

  overlap_length = len(padded_key) // 3
  split_keys = [str(ix) + padded_key[ix * overlap_length : (ix + 1) * overlap_length] for ix in range(3)]
  split_combined = ["".join(comb) for comb in combinations(split_keys, 2)]
  return split_combined
def reconstruct_with_overlap_v2(key1, key2):
  """Reconstructs the original key from two overlapping keys, removing padding."""
  def split_equal(key):
    """Splits a string into two equal halves."""
    length = len(key) // 2
    return [key[:length], key[length:]]

  all_splits = []
  all_splits.extend(split_equal(key1))
  all_splits.extend(split_equal(key2))

  all_splits_unique = list(set(all_splits))  # Remove one duplicate due to combination
  all_splits_unique.sort()  # Sorting would provide right order

  # Remove padding character ('0' in this case) before combining
  #combined_key = "".join([split[:-1] for split in all_splits_unique])
  combined_key = "".join([split[1:] for split in all_splits_unique])

  return combined_key

def send_Email(file_Name,recepient_email,uploaded_by,secret):
      subject = 'File Upload Notification for the user::',uploaded_by
      message = f"""This email is to inform you that a new file named "{file_Name}" has been uploaded by {uploaded_by}. You have been granted the security key is : {secret} to view and download this file.

  *Please note:*

  1. *Access Key:* You have been provided with a separate, secure channel to access the key for this file. *Do not* use the key included in this email (for security reasons).
  2. *Key Security:* The access key (secret) is case-sensitive. Please ensure you enter it exactly as shown in the secure channel. For security purposes, it's recommended to keep this access key confidential and not share it with anyone else.
  3. *Please coordinate with the other key holder to access the file.*
Do you have any questions about accessing the file or require further assistance? Please don't hesitate to contact admin directly or reply to this email.

  Regards,
  Telemedicine Attribute"""
            # Optionally include other relevant information (e.g., filename, upload date)
            # Send email to doctor (ensure doctor's email is accessible)
      send_mail(
                subject,
                message,
                settings.EMAIL_HOST_USER,  
                [recepient_email], 
                fail_silently=False,  # Set to True if errors should be ignored
            )   
def user_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        #role=request.POST['role']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('upload_file')
    return render(request, 'user_login.html')

@login_required
def user_logout(request):
    logout(request)
    return redirect('home')

import random
import string
class FileUploadForm(forms.Form):
    file = forms.FileField()
    doctor = forms.ModelChoiceField(queryset=User.objects.filter(account__user_type='doctor'))

@login_required
def upload_file(request):
    doctors = User.objects.filter(account__user_type='doctor')
    partial_key_user = None  # Initialize partial key for user
    
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            file = form.cleaned_data['file']
            doctor = form.cleaned_data['doctor']
            
            # Generate secret key
            secret_key = generate_secret_key()
            print("originalkey===========>",secret_key)
            secret_key_str = secret_key.decode('utf-8')
            print("secret_key_str======================>>>",secret_key_str)
            # Split the secret key into shares
            shares = split_secret_key(secret_key_str)
            print("shares============================>",shares)
            # Create a Fernet cipher suite with the generated key
            cipher_suite = Fernet(secret_key)
            print("cipher value==================>",cipher_suite)
            # Encrypt file content
            encrypted_content = cipher_suite.encrypt(file.read())
            
            # Save the shares to the database
            file_ins = FileHandle.objects.create(
                user=request.user,
                filename=file.name,
                user_reconstructed_key='',  # Will be reconstructed when needed
                doctor=doctor,
                encrypted_content=encrypted_content,  # Save encrypted content
                content_name='En-'+file.name
            )

            # Save the file data using ContentFile
            #file_ins.file.save(file.name, file)
            #file_ins.encrypted_content.save(file.name,encrypted_content)
            # Prepare email content (avoid sending secret or shares)
            file_name = file.name
            uploaded_by = request.user.username
                        
            # Send email to doctor
            send_Email(file_name, str(doctor) + '@gmail.com', uploaded_by, shares[0])
            
            # Send email to user
            user_email = request.user.username + '@gmail.com'
            send_Email(file_name, user_email, uploaded_by, shares[1])
            
            # Send email to admin
            admin_email = 'telemedicineattribute@gmail.com'
            send_Email(file_name, admin_email, uploaded_by, shares[2])
            
    else:
        form = FileUploadForm()
    
    context = {'form': form, 'doctors': doctors, 'partial_key_user': partial_key_user}
    return render(request, 'upload_file.html', context)   
@login_required
def access_user_data(request):
    curr_user = request.user
    context = {}
    if curr_user.account.user_type == 'doctor':
        # If the user is a doctor, only fetch regular users (not doctors)
        all_accounts = Account.objects.filter(user_type='normal')
    else:
        all_accounts = Account.objects.filter(user=curr_user)
    context['all_accounts'] = all_accounts
    return render(request, 'user_data_list.html', context)


@login_required
def view_files(request):
    context = {}
    # Get the currently logged-in user
    user = request.user
    # Check if the user is a doctor
    if user.account.user_type == 'doctor':
        # Get all files assigned to the current doctor
        doctor_files = FileHandle.objects.filter(doctor=user)
        # Prepare file data for rendering
        list_files = []
        for file in doctor_files:
            list_files.append({
                'id': file.id,
                'filename': file.filename,
                #'filepath': file.file.url,
                'user': file.user.username,
                'encrypted_content': file.encrypted_content,  # Add encrypted content
            })
        context['all_files'] = list_files
        return render(request, 'view_files.html', context)
    else:
        return HttpResponse('<p>You are not authorized to view this page.</p>')


@login_required
def view_each_file(request, file_id):
    file_ins = FileHandle.objects.get(pk=file_id)
    partial_key_doctor = None  # Initialize partial key for doctor

    if hasattr(request.user, 'account') and request.user.account.user_type == 'doctor':
        partial_key_input = request.POST.get('partial_key', '')  # Get the partial key1 provided by the user
        partial_key_input_2 = request.POST.get('partial_key_2', '')  # Get the partial key2 provided by the user

        print("partial_key_input_1=====================>1", partial_key_input)
        print("partial_key_input_2=====================>2", partial_key_input_2)

        reconstructed_key = reconstruct_with_overlap_v2(partial_key_input, partial_key_input_2)
        print("==================>new reconstructed key*******************%$$##$$%%", reconstructed_key)

        # Decryption logic only if reconstructed_key exists
        if reconstructed_key:
            try:
                length_of_key = len(reconstructed_key)
                print("length of reconstructed key ==================", length_of_key)

                # Ensure proper encoding for Fernet (assuming reconstructed_key is a string)
                decrypt_key = reconstructed_key.encode('utf-8')
                print("decrypt_key====post encoding", decrypt_key)

                cipher_suite = Fernet(decrypt_key)
                decrypted_content = cipher_suite.decrypt(file_ins.encrypted_content)

                # Save the decrypted data to a temporary location
                temp_filename = f'temp_files/{file_ins.user_id}_{file_ins.filename}'
                path = default_storage.save(temp_filename, ContentFile(decrypted_content))
                file_url = default_storage.url(path)
                file_type = file_ins.filename.split('.')[-1].lower()

                context = {'file_url': file_url, 'file_type': file_type}
                return render(request, 'display_file.html', context)

            except ValueError as e:
                print("Decryption error:", e)
                # Handle decryption error (e.g., log the error or display an error message to the user)
                context = {'file_ins': file_ins, 'partial_key_doctor': partial_key_doctor, 'decryption_error': True}
                return render(request, 'view_each_file.html', context)

    # If user is not a doctor or key reconstruction fails, return original context
    context = {'file_ins': file_ins, 'partial_key_doctor': partial_key_doctor}
    return render(request, 'view_each_file.html', context)



from .models import Prescription

class PrescriptionForm(forms.ModelForm):
    class Meta:
        model = Prescription
        fields = ['user', 'details']



from django.urls import reverse
from django.http import HttpResponseRedirect   
def test_user_dropdown(request):
    users = User.objects.all()
    if request.method == 'POST':
        selected_user_id = request.POST.get('user_id')
        return HttpResponseRedirect(reverse('send_prescriptions', args=[selected_user_id]))
    return render(request, 'test_dropdown.html', {'users': users})

from django.contrib.auth.decorators import login_required
from .models import Prescription

@login_required
def send_prescriptions(request):
    if request.method == 'POST':
        # Retrieve the selected user ID and prescription details from the form
        user_id = request.POST.get('user_id')
        prescription_details = request.POST.get('prescription')
        prescription_file = request.FILES.get('prescription_file')
        # Retrieve the currently logged-in doctor
        doctor1 = request.user
        # Retrieve the selected user object
        selected_user = User.objects.get(pk=user_id)
        # Create a Prescription object with the selected user, doctor, and prescription details
        Prescription.objects.create(
        user=selected_user,
        details=prescription_details,
        doctor1=doctor1,
        prescription_file=prescription_file
        ) 
         # If a file was uploaded, save it
       # if prescription_file:
       #  Prescription.prescription_file.save(prescription_file.name, prescription_file)
       #  Prescription.save()  # Save the model again after saving the file
        # Redirect to view prescriptions page
        return redirect('view_prescriptions')
    else:
        # If it's a GET request, fetch all users for the dropdown
        normal_users = User.objects.filter(account__user_type='normal')
        
        # Render the send_prescription.html template with the users
        return render(request, 'send_prescription.html', {'users': normal_users})


from django.contrib.auth.decorators import login_required
from .models import Prescription

@login_required
def view_prescriptions(request):
    # Retrieve the currently logged-in user
    user = request.user
    
    # Check if the user is a doctor
    if user.account.user_type == 'doctor':
        # If the user is a doctor, only fetch prescriptions assigned to them
        prescriptions = Prescription.objects.filter(doctor1=user)
    else:
        # If the user is not a doctor, only fetch prescriptions assigned to them as a patient
        prescriptions = Prescription.objects.filter(user=user)
    
    return render(request, 'view_prescriptions.html', {'prescriptions': prescriptions})


from django.shortcuts import render
from django.contrib.auth.models import User

def test_user_dropdown(request):
    users = User.objects.all()
    return render(request, 'test_dropdown.html', {'users': users})
