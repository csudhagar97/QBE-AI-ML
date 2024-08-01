from django.urls import path
from .views import *
from . import views
from django.urls import path
from django.urls import path
from .views import approval_requests, handle_approval_request

urlpatterns = [
    path('', home, name='home'),
    path('register/', user_register, name='user_register'),
    path('login/', user_login, name='user_login'),
    path('logout/', user_logout, name='user_logout'),
    path('upload/', upload_file, name='upload_file'),
    path('user_data_list/', access_user_data, name='access_user_data'),
    path('files/', view_files, name='user_data_list'),
    path('files/<int:file_id>/', view_each_file, name='view_each_file'),
    path('view_prescriptions/', views.view_prescriptions, name='view_prescriptions'),
    path('send_prescriptions/', views.send_prescriptions, name='send_prescriptions'),
    path('approval-requested/', views.approval_requested, name='approval_requested'),
    path('request-approval/', views.request_approval, name='request_approval'),
    path('approval_requests/', views.approval_requests, name='approval_requests'),
    path('files/', view_files, name='view_files'),
    path('handle-approval-request/', views.handle_approval_request, name='handle_approval_request'),
    path('my_doctors/', views.my_doctors, name='my_doctors'),
    path('upload-medical-record/', views.upload_medical_record, name='upload_medical_record'),
    path('view-medical-records/', views.view_medical_records, name='view_medical_records'),
    path('validate-ecg/', views.emergency_access, name='validate_ecg'),  # Add this line
    path('validate_ecg/', views.validate_ecg, name='validate_ecg'),
    path('emergency-access/<int:record_id>/', views.emergency_access, name='emergency_access'),
    


    path('send-notification/', views.send_notification, name='send_notification'),
   # path('test-dropdown/', test_user_dropdown, name='test-dropdown')
]
