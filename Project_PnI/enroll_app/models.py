from django.db import models
from django.contrib.auth.models import AbstractUser


class Role(models.Model):
    ROLE = (('ADMIN', 'admin'), ('PROFESSOR', 'professor'), ('STUDENT', 'student'))
    name = models.CharField(max_length=50, choices=ROLE, unique=True)

    def __str__(self):
        return self.name


class User(AbstractUser):
    STATUS = (('NONE', 'none'), ('REGULAR', 'regular'), ('EXTRAORDINARY', 'extraordinary'))
    role = models.ForeignKey(Role, on_delete=models.PROTECT, null=True)
    status = models.CharField(max_length=50, choices=STATUS, null=True)


class Subject(models.Model):
    CHOICES = (('YES', 'yes'), ('NO', 'no'))
    name = models.CharField(max_length=50, unique=True)
    code = models.CharField(max_length=50, unique=True)
    program = models.TextField()
    ects = models.IntegerField()
    sem_regular = models.IntegerField()
    sem_extraordinary = models.IntegerField()
    elective_subject = models.CharField(max_length=50, choices=CHOICES)
    professor = models.ForeignKey(User, on_delete=models.CASCADE, limit_choices_to={'role__name': 'PROFESSOR'})

    def __str__(self):
        return self.name
    

class Enrollment(models.Model):
    CHOICES = (('ENROLLED', 'enrolled'), ('PASSED', 'passed'), ('FAILED', 'failed'))
    student = models.ForeignKey(User, on_delete=models.CASCADE, limit_choices_to={'role__name': 'STUDENT'})
    subject = models.ForeignKey(Subject, on_delete=models.CASCADE)
    status = models.CharField(max_length=50, choices=CHOICES, default='enrolled')

    class Meta:
        unique_together = ['student', 'subject']

    def __str__(self):
        return f"{self.student.username} - {self.subject.name}"