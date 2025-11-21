# -*- coding: utf-8 -*-
import pandas as pd
import os
import pickle
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import numpy as np

# ==================== CONFIGURATION ====================
LOG_DIR = 'data/'
HISTORY_FILE = os.path.join(LOG_DIR, 'history.csv')
MODEL_FILE = os.path.join(LOG_DIR, 'ai_model.pkl')
# Các cột dữ liệu số học dùng để huấn luyện AI
FEATURE_COLUMNS = ['IP_Encoded', 'User_Encoded', 'Hour_of_Day', 'Day_of_Week', 'Status_Encoded']
# =======================================================

def run_retraining():
    """
    Tải dữ liệu lịch sử, huấn luyện lại mô hình Isolation Forest và lưu.
    Script này được thiết kế để chạy định kỳ qua Cron Job.
    """
    if not os.path.exists(HISTORY_FILE):
        print(f"FATAL: {HISTORY_FILE} not found. Cannot retrain model.")
        return False

    try:
        df = pd.read_csv(HISTORY_FILE)
        
        # 1. Feature Engineering & Encoding
        # Cần tạo lại các LabelEncoder trên toàn bộ dữ liệu lịch sử mới
        le_ip = LabelEncoder()
        le_user = LabelEncoder()
        
        # Mã hóa các trường phân loại thành số
        # (Sử dụng astype(str) để xử lý các giá trị NaN/None nếu có)
        df['IP_Encoded'] = le_ip.fit_transform(df['IP_Address'].astype(str))
        df['User_Encoded'] = le_user.fit_transform(df['Username'].astype(str))
        df['Status_Encoded'] = df['Status'].apply(lambda x: 1 if x == 'SUCCESS' else 0)
        
        # Chọn các cột feature
        X = df[FEATURE_COLUMNS]
        
        print("--- Training Isolation Forest Model ---")
        
        # 2. Huấn luyện Mô hình (Isolation Forest)
        model = IsolationForest(contamination='auto', random_state=42)
        model.fit(X)
        
        # 3. Lưu Mô hình (Ghi đè file cũ)
        with open(MODEL_FILE, 'wb') as f:
            pickle.dump(model, f)
        
        print(f"SUCCESSFULLY RETRAINED MODEL at {datetime.now()}")
        return True
        
    except Exception as e:
        print(f"ERROR during retraining: {e}")
        return False

if __name__ == '__main__':
    run_retraining()
