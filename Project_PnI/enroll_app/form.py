from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import Role, User, Subject, Enrollment



class RoleForm(forms.ModelForm):
    class Meta:
        model = Role
        fields = ['name']

class UserForm(UserCreationForm):
    username = forms.CharField(label='Username')
    email = forms.EmailField(label='Email')
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Confirm password', widget=forms.PasswordInput)


    class Meta(UserCreationForm.Meta):
        model = User
        fields = ['username', 'email', 'password1', 'password2', 'role', 'status']

    def clean(self):
        cleaned_data = super().clean()
        role = cleaned_data.get('name')
        status = cleaned_data.get('status')

        if role and status:
            if role.name in ['ADMIN', 'PROFESSOR'] and status != 'none':
                self.add_error('status', "Status must be 'NONE' for admin or professor roles.")
            elif role.name == 'STUDENT' and status not in ['extraordinary', 'regular']:
                self.add_error('status', "Status must be 'EXTRAORDINARY' or 'REGULAR' for student role.")

        return cleaned_data


class SubjectForm(forms.ModelForm):
    class Meta:
        model = Subject
        fields = '__all__'

class StudentUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email','status']

class ProfessorForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email']

class AdminUpdateForm(forms.ModelForm):
    new_password = forms.CharField(label='New password', widget=forms.PasswordInput, required=False)
    
    class Meta:
        model = User
        fields = ['username', 'email', 'new_password', 'status']


class EnrollmentForm(forms.ModelForm):
    class Meta:
        model = Enrollment
        fields = ['student', 'subject', 'status']

class EnrollmentUpdateForm(forms.ModelForm):
    class Meta:
        model = Enrollment
        fields = ['status']

class EnrollmentAddForm(forms.ModelForm):
    student = forms.ModelChoiceField(queryset=User.objects.filter(role__name='STUDENT'), widget=forms.HiddenInput())
    status = forms.CharField(widget=forms.HiddenInput(), initial='ENROLLED')

    class Meta:
        model = Enrollment
        fields = ['subject', 'student', 'status']

    def __init__(self, *args, **kwargs):
        student_id = kwargs.pop('student_id', None)
        super(EnrollmentAddForm, self).__init__(*args, **kwargs)
        if student_id is not None:
            student = User.objects.get(pk=student_id)
            self.initial['student'] = student

    def save(self, commit=True):
        enrollment = super(EnrollmentAddForm, self).save(commit=False)
        student = self.cleaned_data['student']
        enrollment.student = student
        if commit:
            enrollment.save()
        return enrollment


