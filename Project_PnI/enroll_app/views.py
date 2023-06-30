from django.shortcuts import render, redirect, get_object_or_404
from django.db.models.deletion import ProtectedError
from django.urls import reverse
from django.views import generic
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from .form import UserForm, RoleForm, SubjectForm, EnrollmentForm, AdminUpdateForm, EnrollmentAddForm, EnrollmentUpdateForm
from django.http.response import HttpResponse
from django.contrib.auth.decorators import login_required
from .models import Role, User, Subject, Enrollment





#-----------------------#
#   -   ROLE STATUS -   #
#vvvvvvvvvvvvvvvvvvvvvvv#
def check_is_admin(user):
    return user.role.name == 'ADMIN' if user.role else False

def check_is_professor(user):
    return user.role.name == 'PROFESSOR' if user.role else False

def check_is_student(user):
    return user.role.name == 'STUDENT' if user.role else False

def check_is_admin_or_professor(user):
    return check_is_admin(user) or check_is_professor(user)





#-------------------------------#
#   -   LIST OF STUDENTS    -   #
#vv -    Added for task     - vv#
@login_required(login_url='enroll_app:user_login')
def list_of_students(request):
    admin = check_is_admin(request.user)
    if admin:
        users = User.objects.filter(role__name='STUDENT')
        all_students = []
        for user in users:
            passed_ects = 0
            enrolled_ects = 0
            enrollments = Enrollment.objects.filter(student=user)
            for enrolled in enrollments:
                if enrolled.status == 'ENROLLED':
                    enrolled_ects += enrolled.subject.ects
                elif enrolled.status == 'PASSED':
                    passed_ects += enrolled.subject.ects
            all_students.append({'user': user, 'passed_ects': passed_ects, 'enrolled_ects': enrolled_ects})
        return render(request, 'list_of_students.html', {'all_students': all_students, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")
    
@login_required(login_url='enroll_app:user_login')
def list_details(request, pk):
    admin = check_is_admin(request.user)
    if admin:
        student = get_object_or_404(User, pk=pk, role__name='STUDENT')
        enrolled_subjects = Enrollment.objects.filter(student=student, status='ENROLLED').values_list('subject', flat=True)
        passed_subjects = Enrollment.objects.filter(student=student, status='PASSED').values_list('subject', flat=True)
        enrolled_subjects_list = Subject.objects.filter(pk__in=enrolled_subjects)
        passed_subjects_list = Subject.objects.filter(pk__in=passed_subjects)
        return render(request, 'list_details.html', {'student': student, 'enrolled_subjects': enrolled_subjects_list, 'passed_subjects': passed_subjects_list, 'is_admin': admin})
    else:
        return HttpResponse("ACCESS DENIED - You're not an ADMIN")





#-----------------------#
#   -   ENROLLMENT  -   #
#vvvvvvvvvvvvvvvvvvvvvvv#
@login_required(login_url='enroll_app:user_login')
def enrollment_create(request):
    admin = check_is_admin(request.user)
    if admin:
        if request.method == 'POST':
            form = EnrollmentForm(request.POST)
            if form.is_valid():
                form.save()
                return redirect('enroll_app:enrollment_user')
        else:
            form = EnrollmentForm()
        return render(request, 'enrollment_create.html', {'form': form, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")

@login_required(login_url='enroll_app:user_login')
def enrollment_detail(request, pk, user_id):
    admin = check_is_admin(request.user)
    if admin:
        enrollment = get_object_or_404(Enrollment, pk=pk)
        user = get_object_or_404(User, pk=user_id)
        return render(request, 'enrollment_detail.html', {'user': user, 'enrollment': enrollment, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")

@login_required(login_url='enroll_app:user_login')
def enrollment_list(request, user_id):
    admin = check_is_admin(request.user)
    if admin:
        user = get_object_or_404(User, pk=user_id, role__name='STUDENT')
        enrollments = Enrollment.objects.filter(student=user)
        return render(request, 'enrollment_list.html', {'user': user, 'enrollments': enrollments, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")

@login_required(login_url='enroll_app:user_login')
def enrollment_user(request):
    admin = check_is_admin(request.user)
    if admin:
        users = User.objects.filter(role__name='STUDENT')
        return render(request, 'enrollment_users.html', {'users': users, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")

@login_required(login_url='enroll_app:user_login')
def enrollment_update(request, pk, user_id):
    admin = check_is_admin(request.user)
    if admin:
        enrollment = get_object_or_404(Enrollment, pk=pk)
        user = get_object_or_404(User, pk=user_id)
        if request.method == 'POST':
            form = EnrollmentUpdateForm(request.POST, instance=enrollment)
            if form.is_valid():
                form.save()
                return redirect('enroll_app:enrollment_list', user_id)
        else:
            form = EnrollmentUpdateForm(instance=enrollment)
        return render(request, 'enrollment_update.html', {'user': user, 'form': form, 'enrollment': enrollment, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")

@login_required(login_url='enroll_app:user_login')
def enrollment_delete(request, pk, user_id):
    admin = check_is_admin(request.user)
    if admin:
        enrollment = get_object_or_404(Enrollment, pk=pk)
        user = get_object_or_404(User, pk=user_id)
        if request.method == 'POST':
            enrollment.delete()
            return redirect('enroll_app:enrollment_list', user_id)
        return render(request, 'enrollment_delete.html', {'user': user, 'enrollment': enrollment, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")





#-------------------#
#   -   STUDENT -   #
#vvvvvvvvvvvvvvvvvvv#
@login_required(login_url='enroll_app:user_login')
def student_enrollment_list(request):
    student = check_is_student(request.user)
    if student:
        if request.user.status == "EXTRAORDINARY":
            enrollments = Enrollment.objects.filter(student=request.user).order_by('subject__sem_extraordinary')
            enrolled_subjects = enrollments.values_list('subject', flat=True)  
            subjects_not_enrolled = Subject.objects.exclude(pk__in=enrolled_subjects).order_by('sem_extraordinary')
        else:
            enrollments = Enrollment.objects.filter(student=request.user).order_by('subject__sem_regular')
            enrolled_subjects = enrollments.values_list('subject', flat=True) 
            subjects_not_enrolled = Subject.objects.exclude(pk__in=enrolled_subjects).order_by('sem_regular')
        total_ects = 0
        total_subjects = 0
        for enrolled in enrollments:
            if enrolled.status == 'ENROLLED':
                total_ects += enrolled.subject.ects
                total_subjects += 1
        return render(request, 'student_enrollment_list.html', {'enrollments': enrollments, 'is_student': student, 'subjects_not_enrolled': subjects_not_enrolled, 'total_ects': total_ects, 'total_subjects':total_subjects})
    else:
        return HttpResponse("ACCESS DENIED - You're not a STUDENT")

@login_required(login_url='enroll_app:user_login')
def student_enrollment_add(request):
    student = check_is_student(request.user)
    if student:
        if request.method == 'POST':
            form = EnrollmentAddForm(request.POST, student_id=request.user.id)
            if form.is_valid():
                form.save()
                return redirect('enroll_app:student_enrollment_list')
        else:
            form = EnrollmentAddForm(student_id=request.user.id)
        
        return render(request, 'student_enrollment_add.html', {'form': form, 'is_student':student})
    else:
        return HttpResponse("ACCESS DENIED -  You're not STUDENT")

@login_required(login_url='enroll_app:user_login')
def student_enrollment_detail(request, pk):
    student = check_is_student(request.user)
    if student:
        enrollment = get_object_or_404(Enrollment, pk=pk, student=request.user)
        return render(request, 'student_enrollment_detail.html', {'enrollment': enrollment, 'is_student':student})
    else:
        return HttpResponse("ACCESS DENIED -  You're not STUDENT")

@login_required(login_url='enroll_app:user_login')
def student_enrollment_delete(request, pk):
    student = check_is_student(request.user)
    if student:
        enrollment = get_object_or_404(Enrollment, pk=pk, student=request.user)
        if request.method == 'POST':
            enrollment.delete()
            return redirect('enroll_app:student_enrollment_list')
        return render(request, 'student_enrollment_delete.html', {'enrollment': enrollment, 'is_student':student})
    else:
        return HttpResponse("ACCESS DENIED -  You're not STUDENT")





#-----------------------#
#   -   PROFESSOR   -   #
#vvvvvvvvvvvvvvvvvvvvvvv#
@login_required(login_url='enroll_app:user_login')
def professor_subject_list(request):
    professor = check_is_professor(request.user)
    if professor:
        subjects = Subject.objects.filter(professor=request.user).order_by('name')
        return render(request, 'professor_subject_list.html', {'subjects': subjects, 'is_professor':professor})
    else:
        return HttpResponse("ACCESS DENIED -  You're not PROFESSOR")

@login_required(login_url='enroll_app:user_login')
def professor_subject_enrollment(request, subject_id):
    professor = check_is_professor(request.user)
    if professor:
        subject = get_object_or_404(Subject, pk=subject_id)
        enrollments = subject.enrollment_set.all()
        status = request.GET.get('status', None) 
        if status:
            enrollments = enrollments.filter(status=status)
        return render(request, 'professor_subject_enrollment.html', {'subject': subject, 'enrollments': enrollments, 'is_professor':professor})
    else:
        return HttpResponse("ACCESS DENIED -  You're not PROFESSOR")

@login_required(login_url='enroll_app:user_login')
def professor_subject_enrollment_update(request, subject_id, enrollment_id):
    professor = check_is_professor(request.user)
    if professor:
        enrollment = get_object_or_404(Enrollment, pk=enrollment_id)
        subject = get_object_or_404(Subject, pk=subject_id)
        
        if request.method == 'POST':
            form = EnrollmentUpdateForm(request.POST, instance=enrollment)
            if form.is_valid():
                form.save()
                return redirect('enroll_app:professor_subject_enrollment', subject_id=subject_id)
        else:
            form = EnrollmentUpdateForm(instance=enrollment)
        
        return render(request, 'professor_subject_enrollment_update.html', {'subject':subject, 'form': form, 'enrollment': enrollment, 'is_professor':professor})
    else:
        return HttpResponse("ACCESS DENIED -  You're not PROFESSOR")





#--------------------#
#   -    USER    -   #
#vvvvvvvvvvvvvvvvvvvv#
@login_required(login_url='enroll_app:user_login')
def user_create(request):
    admin = check_is_admin(request.user)
    if admin:   
        if request.method == 'POST':
            form = UserForm(request.POST)
            if form.is_valid():
                form.save()
                return redirect('enroll_app:user_list')
        else:
            form = UserForm()
        return render(request, 'user_create.html', {'form': form, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")

@login_required(login_url='enroll_app:user_login')
def user_list(request):
    admin = check_is_admin(request.user)
    if admin:
        users = User.objects.all()
        return render(request, 'user_list.html', {'users': users, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")
    
@login_required(login_url='enroll_app:user_login')
def admin_list(request):
    admin = check_is_admin(request.user)
    if admin:
        users = User.objects.filter(role__name='ADMIN')
        return render(request, 'user_list.html', {'users': users, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")

@login_required(login_url='enroll_app:user_login')
def professor_list(request):
    admin = check_is_admin(request.user)
    if admin:
        users = User.objects.filter(role__name='PROFESSOR')
        return render(request, 'user_list.html', {'users': users, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")
    
@login_required(login_url='enroll_app:user_login')
def student_list(request):
    admin = check_is_admin(request.user)
    if admin:
        users = User.objects.filter(role__name='STUDENT')
        return render(request, 'user_list.html', {'users': users, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")

@login_required(login_url='enroll_app:user_login')
def user_detail(request, pk):
    admin = check_is_admin(request.user)
    if admin:
        user = get_object_or_404(User, pk=pk)
        return render(request, 'user_detail.html', {'user': user, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")

@login_required(login_url='enroll_app:user_login')
def user_update(request, pk):
    admin = check_is_admin(request.user)
    if admin:
        user = get_object_or_404(User, pk=pk)
        if request.method == 'POST':
            form = AdminUpdateForm(request.POST, instance=user)
            if form.is_valid():
                new_password = form.cleaned_data.get('new_password')
                if new_password:
                    user.set_password(new_password)
                form.save()
                return redirect('enroll_app:user_list')
        else:
            form = AdminUpdateForm(instance=user)
            role = user.role.name if user.role else None
            if role in ['ADMIN', 'PROFESSOR']:
                del form.fields['status']
            else:
                form.fields['status'].widget.attrs['required'] = True
        return render(request, 'user_update.html', {'form': form, 'user': user, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")

@login_required(login_url='enroll_app:user_login')
def user_delete(request, pk):
    admin = check_is_admin(request.user)
    if admin:
        user = get_object_or_404(User, pk=pk)
        if request.method == 'POST':
            user.delete()
            return redirect('enroll_app:user_list')
        return render(request, 'user_delete.html', {'user': user, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")





#-----------------------#
#   -    SUBJECT    -   #
#vvvvvvvvvvvvvvvvvvvvvvv#
@login_required(login_url='enroll_app:user_login')
def subject_create(request):
    admin = check_is_admin(request.user)
    if admin:
        if request.method == 'POST':
            form = SubjectForm(request.POST)
            if form.is_valid():
                form.save()
                return redirect('enroll_app:subject_list')
        else:
            form = SubjectForm()
        return render(request, 'subject_create.html', {'form': form, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")

@login_required(login_url='enroll_app:user_login')
def subject_list(request):
    admin = check_is_admin(request.user)
    if admin:
        subjects = Subject.objects.all().order_by('name')
        return render(request, 'subject_list.html', {'subjects': subjects, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")

@login_required(login_url='enroll_app:user_login')
def subject_enrollment(request, subject_id):
    admin = check_is_admin(request.user)
    if admin:
        subject = get_object_or_404(Subject, pk=subject_id)
        enrollments = subject.enrollment_set.all()
        total_students = 0
        total_extraordinary = 0
        total_regular = 0
        for passed in enrollments:
            if passed.status == 'PASSED':
                total_students += 1
                if passed.student.status == 'EXTRAORDINARY':
                    total_extraordinary += 1
                else:
                    total_regular += 1
        return render(request, 'subject_enrollment.html', {'subject': subject, 'enrollments': enrollments, 'is_admin':admin, 'total_regular':total_regular, 'total_extraordinary':total_extraordinary, 'total_students':total_students})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")

@login_required(login_url='enroll_app:user_login')
def subject_detail(request, pk):
    if check_is_admin_or_professor(request.user):
        subject = get_object_or_404(Subject, pk=pk)
        return render(request, 'subject_detail.html', {'subject': subject})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN or PROFESSOR")
    
@login_required(login_url='enroll_app:user_login')
def subject_update(request, pk):
    admin = check_is_admin(request.user)
    if admin:
        subject = get_object_or_404(Subject, pk=pk)
        if request.method == 'POST':
            form = SubjectForm(request.POST, instance=subject)
            if form.is_valid():
                form.save()
                return redirect('enroll_app:subject_list')
        else:
            form = SubjectForm(instance=subject)
        return render(request, 'subject_update.html', {'form': form, 'subject': subject, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")

@login_required(login_url='enroll_app:user_login')
def subject_delete(request, pk):
    admin = check_is_admin(request.user)
    if admin:
        subject = get_object_or_404(Subject, pk=pk)
        if request.method == 'POST':
            subject.delete()
            return redirect('enroll_app:subject_list')
        return render(request, 'subject_delete.html', {'subject': subject, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")





#--------------------#
#   -    ROLE    -   #
#vvvvvvvvvvvvvvvvvvvv#
@login_required(login_url='enroll_app:user_login')
def role_list(request):
    admin = check_is_admin(request.user)
    if admin:
        roles = Role.objects.all()
        return render(request, 'role_list.html', {'roles': roles, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")

@login_required(login_url='enroll_app:user_login')
def role_detail(request, pk):
    admin = check_is_admin(request.user)
    if admin:
        role = get_object_or_404(Role, pk=pk)
        return render(request, 'role_detail.html', {'role': role, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")

@login_required(login_url='enroll_app:user_login')
def role_create(request):
    admin = check_is_admin(request.user)
    if admin:
        if request.method == 'POST':
            form = RoleForm(request.POST)
            if form.is_valid():
                form.save()
                return redirect('enroll_app:role_list')
        else:
            form = RoleForm()
        return render(request, 'role_create.html', {'form': form, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")

@login_required(login_url='enroll_app:user_login')
def role_update(request, pk):
    admin = check_is_admin(request.user)
    if admin:
        role = get_object_or_404(Role, pk=pk)
        if request.method == 'POST':
            form = RoleForm(request.POST, instance=role)
            if form.is_valid():
                form.save()
                return redirect('enroll_app:role_list')
        else:
            form = RoleForm(instance=role)
        return render(request, 'role_update.html', {'form': form, 'role': role, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")

@login_required(login_url='enroll_app:user_login')
def role_delete(request, pk):
    admin = check_is_admin(request.user)
    if admin:
        role = get_object_or_404(Role, pk=pk)
        if request.method == 'POST':
            try:
                role.delete()
                messages.success(request, f"The role '{role.name}' has been deleted.")
            except ProtectedError:
                messages.error(request, f"Cannot delete the role '{role.name}' because it is referenced by other objects.")
            return redirect('enroll_app:role_list')
        return render(request, 'role_delete.html', {'role': role, 'is_admin':admin})
    else:
        return HttpResponse("ACCESS DENIED -  You're not ADMIN")





#------------------#
#   -  LOGIN   -   #
#vvvvvvvvvvvvvvvvvv#
def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            role = user.role.name  
            if role == 'ADMIN':
                return redirect(reverse('enroll_app:subject_list'))  
            elif role == 'PROFESSOR':
                return redirect(reverse('enroll_app:professor_subject_list'))  
            elif role == 'STUDENT':
                return redirect(reverse('enroll_app:student_enrollment_list'))  
        else:
            message = 'Invalid username or password.'
            return render(request, 'login.html', {'message': message})  
    return render(request, 'login.html')





#-------------------#
#   -   LOGOUT  -   #
#vvvvvvvvvvvvvvvvvvv#
class LogoutView(generic.TemplateView):
    def get(self, request):
        logout(request)
        return redirect(reverse("enroll_app:user_login"))        