# Generated by Django 4.1.2 on 2022-10-21 18:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0006_encrypt_delete_file_doc'),
    ]

    operations = [
        migrations.AlterField(
            model_name='encrypt',
            name='receiver_email',
            field=models.EmailField(max_length=254),
        ),
    ]
