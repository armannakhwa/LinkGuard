

import joblib
import numpy as np
import joblib
from lightgbm import LGBMClassifier

# load the saved model
loaded_model = joblib.load('a.h5')

# Make predictions on new data
features_test = [0, 1, 2, 0, 0, 3, 0, 0, 0, 1, 0, 0, 1, 0, 73, 34, 0, 3, 61, 10, 3]
features_test = np.array(features_test).reshape((1, -1))
# use the loaded model to make predictions on new data
y_pred = loaded_model.predict(features_test)
print("********")
print(y_pred)


