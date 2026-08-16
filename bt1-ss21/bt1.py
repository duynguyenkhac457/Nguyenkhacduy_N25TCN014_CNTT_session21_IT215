import bcrypt

def hash_password(password: str) -> str:
    """
    Băm mật khẩu sử dụng Bcrypt và trả về chuỗi hash.
    """
    # Bcrypt yêu cầu đầu vào là dạng bytes, nên cần encode mật khẩu gốc
    password_bytes = password.encode('utf-8')
    
    # Tạo một salt ngẫu nhiên
    salt = bcrypt.gensalt()
    
    # Băm mật khẩu kết hợp với salt
    hashed_bytes = bcrypt.hashpw(password_bytes, salt)
    
    # Chuyển đổi kết quả từ bytes về chuỗi string để lưu vào database
    return hashed_bytes.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Kiểm tra mật khẩu nhập vào có khớp với mật khẩu đã băm hay không.
    """
    # Encode mật khẩu nhập vào và chuỗi hash về dạng bytes
    password_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    
    # Sử dụng hàm checkpw của bcrypt để so sánh
    return bcrypt.checkpw(password_bytes, hashed_bytes)

# ==========================================
# KIỂM THỬ (TESTING)
# ==========================================
if __name__ == "__main__":
    password = "Rikkei@123"
    
    # 1. Băm mật khẩu
    hashed_password = hash_password(password)
    print(f"Hashed Password: {hashed_password}")
    
    # 2. Kiểm tra với mật khẩu đúng
    is_correct = verify_password("Rikkei@123", hashed_password)
    print(f"Verify 'Rikkei@123': {is_correct}")  # Mong đợi: True
    
    # 3. Kiểm tra với mật khẩu sai
    is_wrong = verify_password("Rikkei@456", hashed_password)
    print(f"Verify 'Rikkei@456': {is_wrong}")    # Mong đợi: False
