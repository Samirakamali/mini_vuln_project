from django.urls import path
from .views import AssetListCreateAPIView, AssetDetailAPIView

urlpatterns = [
    path("assets/", AssetListCreateAPIView.as_view()),
    path("assets/<int:pk>/", AssetDetailAPIView.as_view()),
]
