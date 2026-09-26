from django.urls import path
from . import views


urlpatterns = [

    path(
        "",
        views.home,
        name="home"
    ),

    path(
        "history/",
        views.history,
        name="history"
    ),

    path(
        "dashboard/",
        views.dashboard,
        name="dashboard"
    ),

    path(
        "detection/<int:id>/",
        views.detection_detail,
        name="detection_detail"
    ),

]