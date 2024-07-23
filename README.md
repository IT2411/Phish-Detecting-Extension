# Phish-Detecting-Extension
An extension that detects phishing websites in real time and prevents the user from harm through the use of Machine Learning


[constants.py](https://github.com/IT2411/Phish-Detecting-Extension/blob/main/constants.py) provides a list of shortening services and ccTLDs

[ssl_checker.py](https://github.com/IT2411/Phish-Detecting-Extension/blob/main/ssl_checker.py) allows us to check if the url has a certifacte or not.

[Feature Extraction.py](https://github.com/IT2411/Phish-Detecting-Extension/blob/main/Feature%20Extraction.py) extracts data from the urls provided, features such as 'have_IP', 'multi_domain', 'have_at', 'length', 'redirect', 'hyphen_present', 'short_url', 'dns', 'check_cert', 'domain_age', 'forwarding', 'anchor_urls', 'request_url', 'status'.

[Training_Model.py](https://github.com/IT2411/Phish-Detecting-Extension/blob/main/Training_Model.py) uses 6 different Classifiers such as 'RandomForestClassifier', 'AdaBoostClassifier', 'KNeighborsClassifier', 'GradientBoostingClassifier', 'MLPClassifier', 'XGBClassifier' to train a model. Random Forest and XGBoost providing the highest accuracies. It also has finctions to check feature rankings which helps further in training a model to avoid overfitting, dataleaks or similar circumstances.
