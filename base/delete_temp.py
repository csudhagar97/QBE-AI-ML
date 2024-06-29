# delete_temp_files.py
import os
import datetime
from django.core.management.base import BaseCommand
from django.conf import settings

class Command(BaseCommand):
    help = 'Delete temporary files older than a specified duration'

    def handle(self, *args, **options):
        temp_files_dir = os.path.join(settings.MEDIA_ROOT, 'temp_files')
        threshold_age = datetime.timedelta(days=1)  # Define the threshold age for temporary files
        
        # Iterate through files in the temp directory and delete files older than the threshold
        for filename in os.listdir(temp_files_dir):
            file_path = os.path.join(temp_files_dir, filename)
            modified_time = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
            current_time = datetime.datetime.now()
            age = current_time - modified_time
            if age > threshold_age:
                os.remove(file_path)
                self.stdout.write(self.style.SUCCESS(f'Deleted file: {filename}'))
