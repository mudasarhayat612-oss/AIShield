import os

import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# PATHS
# ============================================================

ML_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DATA_PATH = os.path.join(
    ML_DIR,
    "data",
    "messages.csv"
)

MODEL_DIR = os.path.join(
    ML_DIR,
    "models"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "spam_model.pkl"
)


# Create model directory if it does not exist
os.makedirs(
    MODEL_DIR,
    exist_ok=True
)


# ============================================================
# CHECK DATASET
# ============================================================

print("\nLoading dataset...")

print(
    f"Dataset path: {DATA_PATH}"
)


if not os.path.exists(DATA_PATH):

    print(
        "\nERROR: messages.csv was not found."
    )

    print(
        "Expected location:"
    )

    print(
        DATA_PATH
    )

    raise SystemExit(1)


# ============================================================
# LOAD DATASET
# ============================================================

df = pd.read_csv(
    DATA_PATH
)


print(
    f"\nTotal messages: {len(df)}"
)


print(
    "\nClass distribution:"
)

print(
    df["label"].value_counts()
)


# ============================================================
# BASIC DATA VALIDATION
# ============================================================

required_columns = [
    "id",
    "message",
    "label"
]


for column in required_columns:

    if column not in df.columns:

        raise ValueError(
            f"Missing required column: {column}"
        )


# Remove empty messages
df = df.dropna(
    subset=["message", "label"]
)


# Remove duplicate messages
df = df.drop_duplicates(
    subset=["message"]
)


print(
    f"\nMessages after cleaning: {len(df)}"
)


# ============================================================
# INPUT / OUTPUT
# ============================================================

X = df["message"]

y = df["label"]


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,

    test_size=0.20,

    random_state=42,

    stratify=y
)


print(
    f"\nTraining messages: {len(X_train)}"
)

print(
    f"Testing messages: {len(X_test)}"
)


# ============================================================
# MACHINE LEARNING PIPELINE
# ============================================================

model = Pipeline(

    [

        (
            "tfidf",

            TfidfVectorizer(

                lowercase=True,

                stop_words="english",

                ngram_range=(1, 2),

                sublinear_tf=True,

                min_df=1

            )
        ),

        (
            "classifier",

            LogisticRegression(

                max_iter=2000,

                random_state=42

            )
        )

    ]

)


# ============================================================
# TRAIN MODEL
# ============================================================

print(
    "\nTraining model..."
)


model.fit(
    X_train,
    y_train
)


print(
    "Model trained successfully."
)


# ============================================================
# EVALUATION
# ============================================================

print(
    "\nEvaluating model..."
)


predictions = model.predict(
    X_test
)


accuracy = accuracy_score(
    y_test,
    predictions
)


print(
    f"\nAccuracy: {accuracy * 100:.2f}%"
)


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print(
    "\nClassification Report:"
)


print(
    classification_report(
        y_test,
        predictions,
        zero_division=0
    )
)


# ============================================================
# CONFUSION MATRIX
# ============================================================

print(
    "\nConfusion Matrix:"
)


matrix = confusion_matrix(

    y_test,

    predictions,

    labels=[
        "safe",
        "spam"
    ]

)


print(
    matrix
)


# ============================================================
# SAVE MODEL
# ============================================================

joblib.dump(

    model,

    MODEL_PATH

)


print(
    "\nModel saved successfully:"
)


print(
    MODEL_PATH
)


# ============================================================
# SAMPLE TESTS
# ============================================================

test_messages = [

    "Hello, how are you?",

    "Can you send me the project?",

    "Congratulations! You won Rs. 50,000. Claim your prize now!",

    "URGENT! Verify your account immediately",

    "Please send me the assignment",

    "Click here to claim your free reward",

    "Let's meet tomorrow at 5 PM",

    "Send your OTP to receive your prize"

]


print(
    "\nTesting sample messages..."
)


for message in test_messages:

    prediction = model.predict(
        [message]
    )[0]

    probabilities = (
        model.predict_proba(
            [message]
        )[0]
    )

    confidence = (
        max(probabilities) * 100
    )

    print(
        "\nMessage:"
    )

    print(
        message
    )

    print(
        f"Prediction: {prediction}"
    )

    print(
        f"Confidence: {confidence:.2f}%"
    )


print(
    "\nTraining completed successfully."
)