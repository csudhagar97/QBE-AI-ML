from datetime import datetime, timezone
from itertools import combinations
import json
import logging
import secrets
from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect
from django.core.files.base import ContentFile
from django.http import FileResponse
from django.core.files.storage import default_storage
import requests
import tensorflow as tf

from attribute_telemed import settings
from .models import Approval, FileHandle, Account
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

import hvac
from cryptography.fernet import Fernet
from django.core.files.storage import FileSystemStorage

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from .models import FileHandle, Approval
from django.core.mail import send_mail
from django.conf import settings


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
        email = request.POST['email']
        age = request.POST['age']
        blood_groups = request.POST['blood_groups']
        gender = request.POST['gender']
        medical_note = request.POST['medical_note']
        role = request.POST['role']

        print("user_type======================>>>>>>>>>>>>>",role)
        if password == password2:
            user = User.objects.create_user(username=username, password=password)
            if role in ['medical_staff', 'doctor']:
                user_type = role
            else:
                user_type = 'normal'
            print("user_type======================>>>>>>>>>>>>>",user_type)
            account_ins = Account.objects.create(
                user=user,
                user_type=user_type,
                first_name=first_name,
                last_name=last_name,
                email=email,
                age=age,
                blood_group=blood_groups,
                gender=gender,
                medical_note=medical_note,
                username=username,
                secret_key=''.join([random.choice('abcdefghijklmnopqrstuvwxyz') for i in range(30)])
            )
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
  combined_key = "".join([split[1:] for split in all_splits_unique])

  return combined_key

def send_Email(file_Name,recepient_email,uploaded_by):
      subject = 'File Upload Notification for the user::',uploaded_by
      message = f"""This email is to inform you that a new file named "{file_Name}" has been uploaded by {uploaded_by}.

  Please note:

File Uploaded by User: The file has been uploaded by the user.
Access Request: To access the file, you can raise a request to either the patient or medical staff.
Do you have any questions about accessing the file or require further assistance? Please don't hesitate to contact admin directly or reply to this email.

  Regards,
  Telemedicine Application"""
            # Optionally include other relevant information (e.g., filename, upload date)
            # Send email to doctor (ensure doctor's email is accessible)
      send_mail(
                subject,
                message,
                settings.EMAIL_HOST_USER,  
                [recepient_email], 
                fail_silently=False,  # Set to True if errors should be ignored
            )   
      
      #Function to store key in vault 
def store_key_shares_vault(shares, file_name):
   client = hvac.Client(url=settings.VAULT_ADDR, token=settings.VAULT_TOKEN)
   print("Vault store=================================================")
   client.secrets.kv.v2.create_or_update_secret(
   path=f'key-shares/{file_name}',
   secret={f'share_{i}': share for i, share in enumerate(shares)}
   
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
            user_Account = Account.objects.get(username=uploaded_by)
            user_Email = user_Account.email
            doctor_Account = Account.objects.get(username=doctor)
            doctor_Email = doctor_Account.email
          
            # Send email to doctor
            print("file_name=================================================CALLL",file_name)
            print("doctor_Email=================================================CALLL",doctor_Email)
            print("uploaded_by=================================================CALLL",uploaded_by)
            send_Email(file_name,doctor_Email, uploaded_by)
            
            # Send email to user
            send_Email(file_name, user_Email, uploaded_by)
            
            # Send email to admin
            admin_email = 'telemedicineattribute@gmail.com'
            send_Email(file_name, admin_email, uploaded_by)

            # store key in vault
            print("Vault store=================================================CALLL")
            store_key_shares_vault(shares, file_name)
            print("Vault store=================================================EXIT")
            
    else:
        form = FileUploadForm()
    
    context = {'form': form, 'doctors': doctors, 'partial_key_user': partial_key_user}
    return render(request, 'upload_file.html', context)   
@login_required
def access_user_data(request):
    curr_user = request.user
    context = {}
    if curr_user.account.user_type == 'medical_staff' :
        # If the user is a doctor, only fetch regular users (not doctors)
        all_accounts = Account.objects.all()
    else:
        all_accounts = Account.objects.filter(user_type='normal')
    context['all_accounts'] = all_accounts
    return render(request, 'user_data_list.html', context)

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import FileHandle, Approval
#from .forms import ApprovalRequestForm

@login_required
def view_files(request):
    user = request.user

    if user.account.user_type in ['doctor', 'medical_staff']:
        if user.account.user_type == 'doctor':
         user_files = FileHandle.objects.filter(doctor=user)
        else:
         user_files = FileHandle.objects.all()

        list_files = []
        for file in user_files:
            patient_account = Account.objects.get(user=file.user)
            is_approved_doctor = patient_account.approved_doctors.filter(id=user.id).exists()
            is_approved_for_user = file.approvals.filter(requester=user, approved=True).exists()
            is_approved = is_approved_for_user or is_approved_doctor

            list_files.append({
                'id': file.id,
                'filename': file.filename,
                'user': file.user.username,
                'encrypted_content': file.encrypted_content,
                'is_approved': is_approved
            })

        context = {'all_files': list_files}
        return render(request, 'view_files.html', context)
    else:
        return HttpResponse('<p>You are not authorized to view this page.</p>')




    
import requests
from django.conf import settings
from django.shortcuts import render, get_object_or_404
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.http import JsonResponse, HttpResponse
from cryptography.fernet import Fernet
from .models import FileHandle, Approval
    
def retrieve_key_from_vault(file_name,requester_username):
    client = hvac.Client(url=settings.VAULT_ADDR, token=settings.VAULT_TOKEN)
    try:
        read_response = client.secrets.kv.v2.read_secret_version(path=f'key-shares/{file_name}')
        secret_data = read_response['data']['data']

        # Fetch the relevant shares based on the usernames
        shares = [None, None]
        if requester_username == 'doctor':
            shares = [secret_data.get('share_0'), secret_data.get('share_1')]  # Patient and doctor share
        elif requester_username == 'medical_staff':
            shares = [secret_data.get('share_0'), secret_data.get('share_2')]  # Patient and medical staff share

        return shares
    except hvac.exceptions.VaultError as e:
        print(f"Error retrieving key from Vault: {e}")
        return [None, None]


@login_required
def view_each_file(request, file_id):
    file_ins = get_object_or_404(FileHandle, pk=file_id)
    user_account = Account.objects.get(user=request.user)
    patient_account = Account.objects.get(user=file_ins.user)
    approval_pending = False
    
    logging.info(f"Viewing file {file_id} for user {request.user.username}")
    print("=========user_account.user_type========",user_account.user_type)
    print("=========user_account.username========",user_account.username)
    print("=========Approved doctors======",patient_account.approved_doctors.all())
    # Check if the current user is a doctor and in the patient's approved doctors list
    if user_account.user_type == 'doctor' and user_account.username in [doctor.username for doctor in patient_account.approved_doctors.all()]:
        print("=========APPROVED DOCTOR 1========")
        logging.info(f"User {request.user.username} is a doctor with access")
        vault_shares = retrieve_key_from_vault(file_ins.filename, user_account.user_type)
        patient_key, doctor_key = vault_shares
        print("=====APPROVED DOCTOR VAULT SHARES===================",vault_shares)
        if patient_key and doctor_key:
            reconstructed_key = reconstruct_with_overlap_v2(patient_key, doctor_key)
            if reconstructed_key:
                try:
                    decrypt_key = reconstructed_key.encode('utf-8')
                    cipher_suite = Fernet(decrypt_key)
                    decrypted_content = cipher_suite.decrypt(file_ins.encrypted_content)

                    temp_filename = f'temp_files/{file_ins.user_id}_{file_ins.filename}'
                    path = default_storage.save(temp_filename, ContentFile(decrypted_content))
                    file_url = default_storage.url(path)
                    file_type = file_ins.filename.split('.')[-1].lower()

                    context = {'file_url': file_url, 'file_type': file_type}
                    return render(request, 'display_file.html', context)

                except ValueError as e:
                    logging.error(f"Decryption error for file {file_id}: {e}")
                    context = {'file_ins': file_ins, 'decryption_error': True}
                    return render(request, 'view_each_file.html', context)
            else:
                logging.warning(f"Reconstructed key is None for file {file_id}")
        else:
            logging.warning(f"Patient or doctor key is missing for file {file_id}")
    else:
        # Check if the file has been approved for the specific user
        logging.info(f"Checking approvals for file {file_id}")
        approval = Approval.objects.filter(file=file_ins, requester=request.user, approved=True).exists()
        if approval:
            vault_shares = retrieve_key_from_vault(file_ins.filename, user_account.user_type)
            patient_key, access_key = vault_shares
            print("=====APPROVED File VAULT SHARES===================",vault_shares)
            if patient_key and access_key:
                reconstructed_key = reconstruct_with_overlap_v2(patient_key, access_key)
                if reconstructed_key:
                    try:
                        decrypt_key = reconstructed_key.encode('utf-8')
                        cipher_suite = Fernet(decrypt_key)
                        decrypted_content = cipher_suite.decrypt(file_ins.encrypted_content)

                        temp_filename = f'temp_files/{file_ins.user_id}_{file_ins.filename}'
                        path = default_storage.save(temp_filename, ContentFile(decrypted_content))
                        file_url = default_storage.url(path)
                        file_type = file_ins.filename.split('.')[-1].lower()

                        context = {'file_url': file_url, 'file_type': file_type}
                        return render(request, 'display_file.html', context)

                    except ValueError as e:
                        logging.error(f"Decryption error for file {file_id}: {e}")
                        context = {'file_ins': file_ins, 'decryption_error': True}
                        return render(request, 'view_each_file.html', context)
                else:
                    logging.warning(f"Reconstructed key is None for file {file_id}")
            else:
                logging.warning(f"Patient or access key is missing for file {file_id}")
        else:
            approval_pending = True

    context = {'file_ins': file_ins, 'approval_pending': approval_pending}
    return render(request, 'view_each_file.html', context)






from .models import Prescription

class PrescriptionForm(forms.ModelForm):
    class Meta:
        model = Prescription
        fields = ['user', 'details']

def approval_requested(request):
    # Logic for approval requested view
    return render(request, 'approval_requested.html')  # Replace with your actual template name

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

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import Account
from django.contrib.auth.models import User

@login_required
def my_doctors(request):
    user_account = Account.objects.get(user=request.user)
    doctors = User.objects.filter(account__user_type='doctor')
    if request.method == 'POST':
        selected_doctors = request.POST.getlist('approved_doctors')
        user_account.approved_doctors.set(selected_doctors)
        user_account.save()
        return redirect('my_doctors')
    return render(request, 'my_doctors.html', {'user_account': user_account, 'doctors': doctors})

@login_required
def send_prescriptions(request):
    if request.method == 'POST':
        print("Send prescription")
        return "hi"

from django.contrib.auth.decorators import login_required
from .models import Prescription

@login_required
def view_prescriptions(request):
    # Retrieve the currently logged-in user
    return "hi"

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from .models import FileHandle, Approval
from django.core.mail import send_mail
from django.conf import settings
import json

@require_http_methods(["POST"])
@csrf_exempt
def request_approval(request):
    if request.method == "POST":
        data = json.loads(request.body)
        file_id = data.get('file_id')
        file_ins = get_object_or_404(FileHandle, pk=file_id)
        request_user = Account.objects.get(user=request.user)
        # Send approval request email
        patient = file_ins.user
        patient_account = Account.objects.get(id=patient.id)
        patient_email = patient_account.email
        admin_email = file_ins.user.email  # Replace with actual admin email
        

        if patient_email:
            for email in [patient_email, admin_email]:
                send_mail(
                    'Approval Request for File Access',
                    f'''
                    Dear {email},

                    Doctor {request.user.username} is requesting approval to view the file "{file_ins.filename}". Below are the details:

                    **File Details:**
                    - File Name: {file_ins.filename}
                    - Uploaded By: {file_ins.user.username}

                    **Requester Details:**
                    - Requester Name: {request.user.username}
                    - Requester Role: Doctor/Medical Staff

                    To proceed:
                    1. Log In: Access the login page here and sign in with your credentials.
                    2. Verify Details: Go to the approval section to review the request thoroughly.
                    3. Approve/Reject: Approve or reject the request directly through the application.

                    Do you have any questions about accessing the file or require further assistance? Please don't hesitate to contact admin directly or reply to this email.

                    Best regards,
                    Telemedicine Application
                    ''',
                    settings.DEFAULT_FROM_EMAIL,
                    [email],
                    fail_silently=False,
                )
        else:
            # Handle the case where the patient's email is not available
            messages.error(request, 'Patient email is not available.')

        # Create an Approval entry
        Approval.objects.create(
            file=file_ins,
            file_name=file_ins.filename,
            approver=patient,
            requester=request.user,  # Set the requester field
            requester_type=request_user.user_type  # Set the requester type
        )

        return JsonResponse({'message': 'Approval request has been sent.', 'success': True})



        
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from .models import Approval

@login_required
def approval_requests(request):
    pending_approvals = Approval.objects.filter(approver_id=request.user.id, approved=0)
    
    context = {
        'pending_approvals': [
            {
                'id': approval.id,
                'file_id': approval.file.id,
                'file_name': approval.file.filename,
                'requester': request.user.username,  # Pass the request.user as the requester
            }
            for approval in pending_approvals
        ]
    }

    return render(request, 'approval_requests.html', context)


@require_POST
def handle_approval_request(request):
    if request.method == "POST":
        approval_id = request.POST.get('approval_id')
        action = request.POST.get('action')

        try:
            approval = Approval.objects.get(id=approval_id)
            if action == "approve":
                approval.approved = True
                approval.approval_time = datetime.now()  # Correct way to get the current time
                approval.save()
                messages.success(request, f'Approval request has been {action}d.')
            elif action == "reject":
                approval.delete()  # Delete the approval request if rejected
                messages.success(request, 'Approval request has been rejected and removed.')
        except Approval.DoesNotExist:
            messages.error(request, 'Approval request does not exist.')

    return redirect('approval_requests')
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .forms import MedicalRecordForm
from .models import MedicalRecord

@login_required
def upload_medical_record(request):
    if request.method == 'POST':
        form = MedicalRecordForm(request.POST, request.FILES)
        if form.is_valid():
            medical_record = form.save(commit=False)
            medical_record.user = request.user
            medical_record.save()
            messages.success(request, 'Medical record uploaded successfully!')
            form = MedicalRecordForm()  # Reset form after successful upload
        else:
            messages.error(request, 'There was an error uploading your medical record.')
    else:
        form = MedicalRecordForm()
    return render(request, 'upload_medical_record.html', {'form': form})

from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse
from .models import MedicalRecord
from django.contrib.auth.decorators import login_required

EMERGENCY_CODES = [
    'heart attack', 'stroke', 'allergic reaction', 'asthma attack', 'severe bleeding',
    'unconscious', 'chest pain', 'difficulty breathing', 'severe burn', 'head injury',
    'poisoning', 'drug overdose', 'severe abdominal pain', 'broken bone', 'electric shock',
    'drowning', 'severe allergic reaction', 'anaphylactic shock', 'cardiac arrest', 'seizure',
    'high fever', 'gunshot wound', 'stabbing', 'major trauma', 'hypothermia', 'heat stroke',
    'labor complications', 'miscarriage', 'snake bite', 'scorpion sting'
]
import os
import pandas as pd
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.conf import settings
from .models import MedicalRecord, Account
import json


from django.shortcuts import render, redirect, get_object_or_404
from django.core.files.storage import FileSystemStorage
from django.contrib import messages
import pandas as pd
import tensorflow as tf
from .models import MedicalRecord
import os
from django.conf import settings

import csv
import numpy as np
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import MedicalRecord
import tensorflow as tf

# Load the pre-trained model (ensure this path is correct)
model = tf.keras.models.load_model('D:/Demo Project/23july-onwork/Project_viva/model.h5')
print("============0======================")

@login_required
def emergency_access(request, record_id):
    print("============1======================")
    record = get_object_or_404(MedicalRecord, id=record_id)
    if request.method == 'POST' and request.FILES.get('ecg_report'):
        ecg_report = request.FILES['ecg_report']
        print("============2======================")
        try:
            print("============Inside TRY======================")
            # Read the CSV file and prepare the data for prediction
            data = []
            reader = csv.reader(ecg_report.read().decode('utf-8').splitlines())
            for row in reader:
                data.append(list(map(float, row)))
            data = np.array(data)
            print("============Inside TRY 0=====================")
            # Predict using the model
            prediction = model.predict(data)
            is_abnormal = prediction[0][0] > 0.5  # Adjust this threshold as necessary

            if is_abnormal:
                # Call send_notification function
                send_notification_data = {
                    'record_id': record.id
                }
                send_notification(request, send_notification_data)
                
                return redirect(record.file.url)
            else:
                error_message = "The ECG report indicates a normal heartbeat. Access denied."
        except Exception as e:
            error_message = f"Error processing ECG report: {e}"
    else:
        error_message = None
        print("============Inside TRY 1=====================")
    return render(request, 'emergency_access.html', {'record': record, 'error_message': error_message})


@login_required
@require_POST
def send_notification(request, data):
    record_id = data.get('record_id')

    try:
        record = get_object_or_404(MedicalRecord, pk=record_id)
        record_uploader = Account.objects.get(user=record.user_id)
        file_name = record.file.name.split('/')[-1]

        send_mail(
            'Emergency File View Notification',
            f'''
            Dear {record_uploader.username},

            {request.user.username} has viewed the file "{file_name}". Below are the details:

            **File Details:**
            - File Name: {file_name}
            - Uploaded By: {record_uploader.username}

            **Viewer Details:**
            - Viewer Name: {request.user.username}
            - Viewer Role: Doctor/Medical Staff

            If you have any questions about this file access or require further assistance, please don't hesitate to contact the admin directly or reply to this email.

            Best regards,
            Telemedicine Application
            ''',
            settings.DEFAULT_FROM_EMAIL,
            [record_uploader.email],
            fail_silently=False,
        )
        return JsonResponse({'success': True, 'message': 'Notification sent successfully.'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)})


import os
import pandas as pd
import numpy as np
import tensorflow as tf
from django.shortcuts import render, redirect
from django.core.files.storage import FileSystemStorage
from django.conf import settings

# Load the trained model
model_path = os.path.join(settings.BASE_DIR, 'model.h5')
model = tf.keras.models.load_model(model_path)

from django.shortcuts import render, redirect
from django.core.files.storage import FileSystemStorage
import pandas as pd
import numpy as np
import os
from django.conf import settings
from .models import MedicalRecord  # Import your MedicalRecord model

def validate_ecg(request):
    if request.method == 'POST':
        ecg_file = request.FILES['ecg_file']
        fs = FileSystemStorage()
        filename = fs.save(ecg_file.name, ecg_file)
        uploaded_file_url = fs.url(filename)

        # Load and preprocess the uploaded ECG CSV file
        df = pd.read_csv(os.path.join(settings.MEDIA_ROOT, filename))
        x_ecg = df.values

        if x_ecg.shape[1] != 188:
            error = "Invalid ECG file format. Expected 188 columns."
            return render(request, 'emergency_access.html', {'error': error})

        # Predict using the trained model
        predictions = (model.predict(x_ecg) > 0.5).astype("int32")
        abnormal_count = np.sum(predictions)

        # Logic to provide access based on prediction
        if abnormal_count > 0:
            # Example logic to provide access - customize as needed
            record_id = request.POST.get('record_id')
            if not record_id:
                error = "Record ID is missing."
                return render(request, 'emergency_access.html', {'error': error})

            try:
                medical_record = MedicalRecord.objects.get(id=record_id)
                # Grant access (this logic depends on your implementation)
                # ...
                return redirect('access_granted_url', record_id=medical_record.id)
            except MedicalRecord.DoesNotExist:
                error = "Medical record not found."
                return render(request, 'emergency_access.html', {'error': error})
        else:
            error = "ECG does not indicate an emergency."
            return render(request, 'emergency_access.html', {'error': error})

    return render(request, 'emergency_access.html')



@login_required
def view_medical_records(request):
    records = MedicalRecord.objects.all()
    return render(request, 'view_medical_records.html', {'records': records})




