from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
import xgboost as xgb
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import pandas as pd
from sklearn.model_selection import cross_val_score
import pickle
import matplotlib.pyplot as plt
import numpy as np




# Load the dataset
file_path = 'F:\main_python_env\Phishing project\Dataset\Final_dataset.csv'
data = pd.read_csv(file_path)


# Display the first few rows of the dataset to understand its structure
#data.head(), data.info()


# Convert the target variable to numerical
label_encoder = LabelEncoder()
data['status'] = label_encoder.fit_transform(data['status'])

#Shuffling the dataset
data = data.sample(frac=1, random_state=42).reset_index(drop=True)


# Split the data into features (X) and target (y)
X = data.drop(columns=['domain', 'status'])
y = data['status']


# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.1, random_state=42)

#print(X_train.shape, X_test.shape, y_train.shape, y_test.shape)


#RandomForest Model
rfc_model = RandomForestClassifier()

# AdaBoost Model
ada_model = AdaBoostClassifier()

#KNeighbors Model
knn_model =  KNeighborsClassifier()

#GradientBoosting Model
gbc_model = GradientBoostingClassifier()

#MLP Model
mlp_model = MLPClassifier()

#XGBoost Model
xgb_model = xgb.XGBClassifier()

#
modelset = [rfc_model,ada_model,knn_model,gbc_model,mlp_model,xgb_model]

result = {}

for mod in modelset:
    
    mod.fit(X_train, y_train)
    y_pred = mod.predict(X_test)

    # Evaluate the model
    accuracy = accuracy_score(y_test, y_pred)
    #report = classification_report(y_test, y_pred, target_names=[str(status) for status in label_encoder.classes_])
    #conf_matrix = confusion_matrix(y_test, y_pred)
    cross_val_scores = cross_val_score(mod, X, y, cv=5, scoring='accuracy')

    result[str(mod).split("(")[0]] = {"Accuracy":accuracy, "Mean accuracy":cross_val_scores.mean(), "Standard deviation":cross_val_scores.std()}
    
    with open(f"F:\main_python_env\Phishing project\Models\{str(mod).split('(')[0]}.pkl", 'wb') as file:
        pickle.dump(mod, file)

resultset = pd.DataFrame(result)
print(resultset)




#More optional functions
'''
# Print the results
print("Accuracy:", accuracy)
print("Classification Report:\n", report)
print("Confusion Matrix:\n", conf_matrix)


# Display cross-validation scores
print("Cross-validation scores:", cross_val_scores)
print("Mean accuracy:", cross_val_scores.mean())
print("Standard deviation:", cross_val_scores.std())
'''


#Viewing how important features are (their weight)
def feature_importance(model):
    # Feature importance
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]

    # Print the feature ranking
    print("Feature ranking:")

    for f in range(X.shape[1]):
        print(f"{f + 1}. feature {indices[f]} ({importances[indices[f]]})")



