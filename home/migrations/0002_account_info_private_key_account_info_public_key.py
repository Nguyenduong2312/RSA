# Generated by Django 4.1.2 on 2022-10-21 09:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='account_info',
            name='private_key',
            field=models.BinaryField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='account_info',
            name='public_key',
            field=models.BinaryField(blank=True, null=True),
        ),
    ]
