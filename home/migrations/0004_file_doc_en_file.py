# Generated by Django 4.1.2 on 2022-10-21 10:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0003_rename_field_name_file_doc_file'),
    ]

    operations = [
        migrations.AddField(
            model_name='file_doc',
            name='en_file',
            field=models.FileField(default='name.txt', max_length=254, upload_to=''),
        ),
    ]
