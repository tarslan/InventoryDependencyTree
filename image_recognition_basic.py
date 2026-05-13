import numpy as np
import tensorflow as tf

keras = tf.keras
layers = tf.keras.layers

def main():
    # 1) Load a tiny built-in dataset (CIFAR-10: 32x32 color images, 10 classes)
    (x_train, y_train), (x_test, y_test) = keras.datasets.cifar10.load_data()

    class_names = [
        "airplane", "automobile", "bird", "cat", "deer",
        "dog", "frog", "horse", "ship", "truck"
    ]

    # 2) Normalize pixel values to [0, 1]
    x_train = x_train.astype("float32") / 255.0
    x_test  = x_test.astype("float32") / 255.0

    # 3) Build a very small CNN
    model = keras.Sequential([
        layers.Input(shape=(32, 32, 3)),

        layers.Conv2D(32, (3, 3), activation="relu"),
        layers.MaxPooling2D(),

        layers.Conv2D(64, (3, 3), activation="relu"),
        layers.MaxPooling2D(),

        layers.Flatten(),
        layers.Dense(64, activation="relu"),
        layers.Dense(10, activation="softmax"),
    ])

    model.compile(
        optimizer="adam",
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"]
    )

    model.summary()

    # 4) Train (keep epochs small for "basic" + quick run)
    history = model.fit(
        x_train, y_train,
        validation_split=0.1,
        epochs=5,
        batch_size=64,
        verbose=2
    )

    # 5) Evaluate
    test_loss, test_acc = model.evaluate(x_test, y_test, verbose=0)
    print(f"\nTest accuracy: {test_acc:.4f}")

    # 6) Predict a few images
    idxs = np.random.choice(len(x_test), size=5, replace=False)
    preds = model.predict(x_test[idxs], verbose=0)  # shape: (5, 10)
    pred_labels = np.argmax(preds, axis=1)

    print("\nSample predictions:")
    for i, idx in enumerate(idxs):
        true_label = int(y_test[idx][0])
        pred_label = int(pred_labels[i])
        confidence = float(np.max(preds[i]))

        print(
            f"Image #{idx:5d} | "
            f"True: {class_names[true_label]:10s} | "
            f"Pred: {class_names[pred_label]:10s} | "
            f"Conf: {confidence:.2f}"
        )

    # 7) Save the model (optional)
    model.save("basic_cifar10_cnn.keras")
    print("\nSaved model to basic_cifar10_cnn.keras")

if __name__ == "__main__":
    main()