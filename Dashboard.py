# -*- coding: utf-8 -*-
import streamlit as st
import pandas as pd
import sqlite3
import os

# ==================== CONFIGURATION ====================
DB_FILE = os.path.join('data', 'alerts.db')
# =======================================================

def get_alerts_data():
    """Tải tất cả dữ liệu cảnh báo từ Database."""
    if not os.path.exists(DB_FILE):
        st.error("LỖI: Không tìm thấy Database. Hãy đảm bảo chạy db_manager.py trước.")
        return pd.DataFrame()

    try:
        conn = sqlite3.connect(DB_FILE)
        df = pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp DESC", conn)
        conn.close()
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df
    except Exception as e:
        st.error(f"LỖI DB: Không thể đọc dữ liệu cảnh báo. {e}")
        return pd.DataFrame()

# Đã sửa lỗi: Dùng st.cache để tương thích với phiên bản 1.10.0
@st.cache(ttl=10, allow_output_mutation=True)
def load_data():
    """Hàm wrapper có cache để tải dữ liệu, giúp làm mới nhanh hơn."""
    return get_alerts_data()

def run_dashboard():
    st.set_page_config(layout="wide")
    st.title("SSH Anomaly Detection Dashboard (SIEM Lite)")

    if st.button('Làm mới Dữ liệu', key='refresh'):
        st.legacy_caching.clear_cache()
        
    df = load_data()
    
    if df.empty:
        st.warning("Database trống hoặc có lỗi khi tải dữ liệu.")
        return

    # --- 1. HIỂN THỊ CHỈ SỐ (KPIs) ---
    st.header("1. Tóm Tắt Hoạt động")
    
    col1, col2, col3, col4 = st.columns(4)
    
    df_display = df.copy()
    df_display['is_handled'] = df_display['is_handled'].fillna('PENDING')
    
    blocked_count = df_display[df_display['is_handled'] == 'BLOCKED'].shape[0]
    ai_count = df_display[df_display['detection_type'] == 'AI'].shape[0]
    critical_count = df_display[df_display['severity'] >= 9].shape[0]

    col1.metric("Tổng Cảnh báo (Total)", df.shape[0])
    col2.metric("Số vụ đã chặn (Blocked)", blocked_count)
    col3.metric("Phát hiện AI (Severity 8)", ai_count)
    col4.metric("Cảnh báo Nguy hiểm (Sev 9+)", critical_count)

    st.markdown("---")

    # --- 2. BIỂU ĐỒ PHÂN BỐ CẢNH BÁO ---
    st.header("2. Phân Tích Dữ Liệu")
    
    # Biểu đồ 1: Phân bố theo Mức độ Nghiêm trọng
    st.subheader("Phân bố theo Mức độ Nghiêm trọng (Severity)")
    severity_counts = df['severity'].value_counts().reset_index()
    severity_counts.columns = ['Severity', 'Count']
    st.bar_chart(severity_counts.set_index('Severity'))
    
    # Biểu đồ 2: Hoạt động theo Giờ trong Ngày
    st.subheader("Hoạt động theo Giờ trong Ngày")
    df['hour'] = df['timestamp'].dt.hour
    hourly_alerts = df.groupby('hour').size().reset_index(name='Count')
    st.line_chart(hourly_alerts.set_index('hour'))
    
    st.markdown("---")

    # --- 3. BẢNG CẢNH BÁO CHI TIẾT ---
    st.header("3. Bảng Cảnh Báo Chi Tiết")
    
    # Chuẩn bị dữ liệu hiển thị và lọc
    df_display['is_handled'] = df_display['is_handled'].fillna('PENDING')

    # Thêm bộ lọc
    cols_filter = st.columns(2)
    
    status_options = ['Tất cả'] + list(df_display['is_handled'].unique())
    status_filter = cols_filter[0].selectbox('Lọc theo Trạng thái Xử lý:', status_options)
    
    type_options = ['Tất cả'] + list(df_display['detection_type'].unique())
    type_filter = cols_filter[1].selectbox('Lọc theo Loại Phát hiện:', type_options)
    
    # Áp dụng bộ lọc
    if status_filter != 'Tất cả':
        df_display = df_display[df_display['is_handled'] == status_filter]
    if type_filter != 'Tất cả':
        df_display = df_display[df_display['detection_type'] == type_filter]

    # Hiển thị bảng (Đã sửa lỗi use_container_width)
    st.dataframe(df_display.drop(columns=['id']), height=500)

if __name__ == '__main__':
    run_dashboard()
