# Generated by Django 4.2.2 on 2023-06-30 10:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('enroll_app', '0009_alter_enrollment_student_alter_role_name_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='subject',
            old_name='sem_izvanredni',
            new_name='sem_extraordinary',
        ),
        migrations.RenameField(
            model_name='subject',
            old_name='sem_redovni',
            new_name='sem_regular',
        ),
        migrations.AlterField(
            model_name='subject',
            name='elective_subject',
            field=models.CharField(choices=[('YES', 'yes'), ('NO', 'no')], max_length=50),
        ),
        migrations.AlterField(
            model_name='user',
            name='status',
            field=models.CharField(choices=[('NONE', 'none'), ('REGULAR', 'regular'), ('EXTRAORDINARY', 'extraordinary')], max_length=50, null=True),
        ),
    ]
