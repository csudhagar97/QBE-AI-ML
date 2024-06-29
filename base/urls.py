from django.urls import path
from .views import *
from . import views

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
   # path('test-dropdown/', test_user_dropdown, name='test-dropdown')

]
