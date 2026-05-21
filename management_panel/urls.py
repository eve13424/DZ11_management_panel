from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("reset/", views.reset_demo, name="reset_demo"),
    path("metrics/", views.metrics, name="metrics"),
]
