# Generated by Django 4.2.2 on 2023-06-23 09:38

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('enroll_app', '0005_subject_enrollment'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='role',
        ),
        migrations.AddField(
            model_name='user',
            name='user_role',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.PROTECT, to='enroll_app.role'),
        ),
    ]
