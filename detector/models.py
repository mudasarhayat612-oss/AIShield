from django.db import models


class Detection(models.Model):

    message = models.TextField()

    risk_score = models.IntegerField(default=0)

    risk_level = models.CharField(max_length=20)

    status = models.CharField(max_length=100)

    detected_urls = models.TextField(
        blank=True
    )

    matched_keywords = models.TextField(
        blank=True
    )

    ml_prediction = models.CharField(
        max_length=50,
        default="unavailable"
    )

    ml_confidence = models.IntegerField(
        default=0
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):

        return (
            f"{self.risk_level} - "
            f"{self.risk_score}%"
        )