
from django.urls import path
from secure_url import views


urlpatterns = [
    path(r'service-endpoint/', views.Service.as_view(), name='service'),
    path(
        r'service-endpoint/ip/<str:ip>/',
        views.ServiceIP.as_view(),
        name='service'
    ),
    path(
        r'service-endpoint/domain/<str:domain>/',
        views.ServiceDomain.as_view(),
        name='service'
    ),
]
