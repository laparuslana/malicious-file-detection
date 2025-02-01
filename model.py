import joblib
import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import cross_val_score


model_dir = "model"

os.makedirs(model_dir, exist_ok=True)

# Load the CSV file into a DataFrame
csv_path = os.path.join(model_dir, 'file_features_with_labels.csv')
df = pd.read_csv(csv_path)

df = df.dropna()

label_encoder = LabelEncoder()
df['Extension'] = label_encoder.fit_transform(df['Extension'])
df['SHA-256 Hash'] = label_encoder.fit_transform(df['SHA-256 Hash'])

features = ['Size (bytes)', 'Entropy', 'Extension', "SHA-256 Hash"]
target = 'Label'

X = df[features]
y = df[target]

# Normalize the features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Split the dataset into training and testing sets (80%-20%)
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Initialize and train the Random Forest Classifier
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

# Make predictions
y_pred = rf_model.predict(X_test)

# Evaluate the model
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Classification Report:")
print(classification_report(y_test, y_pred))

# Feature importance
feature_importances = pd.DataFrame(rf_model.feature_importances_,
                                   index=features,
                                   columns=["importance"]).sort_values("importance", ascending=False)
print("Feature Importances:")
print(feature_importances)

# Cross-validation for more robust evaluation
cv_scores = cross_val_score(rf_model, X_scaled, y, cv=5)
print(f"Cross-validation accuracy: {cv_scores.mean()} ± {cv_scores.std()}")


joblib.dump(rf_model, os.path.join(model_dir, 'file_classification_model.pkl'))
pd.to_pickle(label_encoder, os.path.join(model_dir, 'label_encoder.pkl'))
pd.to_pickle(scaler.mean_, os.path.join(model_dir, 'scaler_mean.pkl'))
pd.to_pickle(scaler.scale_, os.path.join(model_dir, 'scaler_scale.pkl'))