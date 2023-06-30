from django.urls import path
from . import views

app_name = "enroll_app"
urlpatterns = [

    #   LIST OF STUDENT(Added for task)
    path('list/', views.list_of_students, name='list_of_students'),
    path('list_detail/<int:pk>', views.list_details, name='list_details'),

    #   ENROLL    
    path('enrollment/', views.enrollment_user, name='enrollment_user'),
    path('enrollment_list/<int:user_id>/enrollment/<int:pk>/', views.enrollment_detail, name='enrollment_detail'),
    path('enrollment/create/', views.enrollment_create, name='enrollment_create'),
    path('enrollment_list/<int:user_id>/<int:pk>/update/', views.enrollment_update, name='enrollment_update'),
    path('enrollment_list/<int:user_id>/enrollment/<int:pk>/delete/', views.enrollment_delete, name='enrollment_delete'),
    path('enrollment_list/<int:user_id>/', views.enrollment_list, name='enrollment_list'),

    #   STUDENT
    path('student_enrollment/', views.student_enrollment_list, name='student_enrollment_list'),
    path('student_enrollment/add/', views.student_enrollment_add, name='student_enrollment_add'),
    path('student_enrollment/<int:pk>/', views.student_enrollment_detail, name='student_enrollment_detail'),
    path('student_enrollment/<int:pk>/delete/', views.student_enrollment_delete, name='student_enrollment_delete'),

    #   USER
    path('users/', views.user_list, name='user_list'),
    path('users/admins/', views.admin_list, name='admin_list'),
    path('users/professors/', views.professor_list, name='professor_list'),
    path('users/students/', views.student_list, name='student_list'),
    path('users/create/', views.user_create, name='user_create'),
    path('users/<int:pk>/', views.user_detail, name='user_detail'),
    path('users/<int:pk>/update/', views.user_update, name='user_update'),
    path('users/<int:pk>/delete/', views.user_delete, name='user_delete'),

    #   SUBJECT
    path('subjects/', views.subject_list, name='subject_list'),
    path('subjects/create/', views.subject_create, name='subject_create'),
    path('subjects/<int:pk>/', views.subject_detail, name='subject_detail'),
    path('subjects/<int:pk>/update/', views.subject_update, name='subject_update'),
    path('subjects/<int:pk>/delete/', views.subject_delete, name='subject_delete'),
    path('subject/<int:subject_id>/enrollment/', views.subject_enrollment, name='subject_enrollment'),

    #   PROFESSOR
    path('professor_subjects/', views.professor_subject_list, name='professor_subject_list'),
    path('professor_subjects_enrollment/<int:subject_id>/', views.professor_subject_enrollment, name='professor_subject_enrollment'),
    path('professor_subjects_enrollment/<int:subject_id>/update/<int:enrollment_id>/', views.professor_subject_enrollment_update, name='professor_subject_enrollment_update'),

    #   ROLE
    path('roles/', views.role_list, name='role_list'),
    path('roles/create/', views.role_create, name='role_create'),
    path('roles/<int:pk>/', views.role_detail, name='role_detail'),
    path('roles/<int:pk>/update/', views.role_update, name='role_update'),
    path('roles/<int:pk>/delete/', views.role_delete, name='role_delete'),

    #   AUTH
    path("login/", views.user_login, name="user_login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
]
