import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import tensorflow as tf

# Define paths to your CSV files
train_file_path = 'D:/Demo Project/23july-onwork/Project_viva/train.csv'
validate_file_path = 'D:/Demo Project/23july-onwork/Project_viva/validate.csv'
test_file_path = 'D:/Demo Project/23july-onwork/Project_viva/test.csv'

# Check if the files exist
if not os.path.exists(train_file_path):
    raise FileNotFoundError(f"No such file: '{train_file_path}'")
if not os.path.exists(validate_file_path):
    raise FileNotFoundError(f"No such file: '{validate_file_path}'")
if not os.path.exists(test_file_path):
    raise FileNotFoundError(f"No such file: '{test_file_path}'")

# Load Data
# Training dataset
df = pd.read_csv(train_file_path)
x_train = df.values[:, :-1]
y_train = df.values[:, -1].astype(int)

# Validation dataset
df = pd.read_csv(validate_file_path)
x_validate = df.values[:, :-1]
y_validate = df.values[:, -1].astype(int)

# Test dataset
df = pd.read_csv(test_file_path)
x_test = df.values[:, :-1]
y_test = df.values[:, -1].astype(int)

del df

# Verify dimensions
print(f'x_train shape: {x_train.shape}')
print(f'y_train shape: {y_train.shape}')
print(f'x_validate shape: {x_validate.shape}')
print(f'y_validate shape: {y_validate.shape}')
print(f'x_test shape: {x_test.shape}')
print(f'y_test shape: {y_test.shape}')

# Check data balance
print("Training data balance:")
print(pd.Series(y_train).value_counts())

print("Validation data balance:")
print(pd.Series(y_validate).value_counts())

print("Test data balance:")
print(pd.Series(y_test).value_counts())

# Visualize Data
# Display one Normal, and one Abnormal heartbeat.
C0 = np.argwhere(y_train == 0).flatten()
C1 = np.argwhere(y_train == 1).flatten()

x = np.arange(0, 188) * 8 / 1000.0  # Adjusted to match the data dimensions

plt.figure(figsize=(20, 12))
if len(C0) > 0:
    plt.plot(x, x_train[C0[0], :], label="Normal")  # Display first normal beat.
else:
    print("No normal heartbeats found in the training data.")

if len(C1) > 0:
    plt.plot(x, x_train[C1[0], :], label="Abnormal")  # Display first abnormal beat.
else:
    print("No abnormal heartbeats found in the training data.")

if len(C0) > 0 or len(C1) > 0:
    plt.legend()
    plt.title("1-beat ECG for every category", fontsize=20)
    plt.ylabel("Normalized Amplitude (0 - 1)", fontsize=15)
    plt.xlabel("Time (ms)", fontsize=15)
    plt.show()

# Train Model using Keras
model = tf.keras.models.Sequential([
    tf.keras.layers.Dense(256, activation='relu', input_shape=(188,)),
    tf.keras.layers.Dropout(0.1),
    tf.keras.layers.Dense(64, activation='relu'),
    tf.keras.layers.Dropout(0.1),
    tf.keras.layers.Dense(16, activation='relu'),
    tf.keras.layers.Dropout(0.1),
    tf.keras.layers.Dense(1, activation='sigmoid')
])

model.compile(optimizer=tf.keras.optimizers.Adam(1e-4),
              loss='binary_crossentropy',
              metrics=['accuracy'])

model.fit(x_train, y_train, epochs=100, batch_size=50, validation_data=(x_validate, y_validate))

# Validate Model
loss, accuracy = model.evaluate(x_validate, y_validate)
print('\nValidation Accuracy: {:.2f}%'.format(accuracy * 100))

# Test Model
predictions = (model.predict(x_test) > 0.5).astype("int32")

totvals = 0
totwrong = 0

for prediction, expected in zip(predictions, y_test):
    totvals += 1
    catpred = prediction[0]
    if expected != catpred:
        totwrong += 1
        print('Real: ', expected, ', pred: ', catpred)

print('Accuracy: ', ((totvals - totwrong) * 100.0 / totvals))
print('Wrong: ', totwrong, ' out of ', totvals)

# Save the model
model.save('D:/Demo Project/23july-onwork/Project_viva/model.h5')
