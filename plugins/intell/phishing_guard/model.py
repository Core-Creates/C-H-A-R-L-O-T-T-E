# plugins/intell/phishing_guard/model.py
import joblib, numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, precision_recall_fscore_support

FEATURE_KEYS = [
    "len_url","len_path","num_params","subdomain_depth","hex_escaped_ratio",
    "entropy_host","entropy_path","digit_ratio_host","port_specified",
    "has_ip_host","contains_at_symbol",
    # page
    "has_pwd_field","emails_found","js_obfuscation_score","word_count","num_forms",
    # tls
    "cert_mismatch",
]

def vectorize(url_f, page_f, tls_f):
    f = {**url_f, **page_f, **tls_f}
    return np.array([float(bool(f[k])) if isinstance(f[k], bool) else float(f[k]) for k in FEATURE_KEYS], dtype=float)

def train(X, y, out_path="plugins/intell/phishing_guard/resources/phish_gbm.joblib"):
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=7)
    clf = GradientBoostingClassifier(random_state=7)
    clf.fit(Xtr, ytr)
    preds = clf.predict_proba(Xte)[:,1]
    auc = roc_auc_score(yte, preds)
    p,r,f,_ = precision_recall_fscore_support(yte, (preds>0.5), average="binary")
    joblib.dump(clf, out_path)
    return {"auc": auc, "precision": p, "recall": r, "f1": f}
