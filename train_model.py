import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib
import time
import sys


def main():
	try:
		print("Loading dataset 'mini_spam_dataset.csv'...")
		df = pd.read_csv("mini_spam_dataset.csv")  # two columns: text, label
		print(f"Dataset loaded: {len(df)} rows")

		if 'text' not in df.columns or 'label' not in df.columns:
			print("ERROR: Dataset must contain 'text' and 'label' columns", file=sys.stderr)
			sys.exit(1)

		print("Class distribution:")
		print(df['label'].value_counts().to_string())

		vectorizer = TfidfVectorizer(stop_words="english")
		X = vectorizer.fit_transform(df["text"])
		y = df["label"]

		clf = LogisticRegression(max_iter=1000)
		print("Training classifier...")
		t0 = time.time()
		clf.fit(X, y)
		elapsed = time.time() - t0
		print(f"Training completed in {elapsed:.2f} seconds")

		train_acc = clf.score(X, y)
		print(f"Training accuracy: {train_acc:.4f}")

		clf_path = "spam_classifier.joblib"
		vec_path = "vectorizer.joblib"
		joblib.dump(clf, clf_path)
		joblib.dump(vectorizer, vec_path)
		print(f"Saved classifier to '{clf_path}'")
		print(f"Saved vectorizer to '{vec_path}'")

	except Exception as e:
		print("ERROR during training:", e, file=sys.stderr)
		sys.exit(1)


if __name__ == "__main__":
	main()
