# Generated by Django 4.1.2 on 2022-10-21 16:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0005_account_info_public_key1'),
    ]

    operations = [
        migrations.CreateModel(
            name='Encrypt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('receiver_email', models.EmailField(max_length=254, unique=True)),
                ('file', models.FileField(default='name.txt', max_length=254, upload_to='')),
                ('en_file', models.FileField(default='name.txt', max_length=254, upload_to='')),
            ],
        ),
        migrations.DeleteModel(
            name='File_doc',
        ),
    ]
