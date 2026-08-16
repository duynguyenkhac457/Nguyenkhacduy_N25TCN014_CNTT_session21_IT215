import jwt
from datetime import datetime, timedelta, timezone

# Khai báo cấu hình cho JWT
SECRET_KEY = "my_super_secret_key_for_jwt"  # Trong thực tế, chuỗi này nên được lưu ở file .env
ALGORITHM = "HS256"

def create_access_token(data: dict, expires_minutes: int) -> str:
    """
    Tạo một JWT access token với payload và thời gian hết hạn.
    """
    # Tạo bản sao của data để không làm thay đổi dữ liệu gốc
    to_encode = data.copy()
    
    # Tính toán thời gian hết hạn (sử dụng timezone.utc theo khuyến cáo mới của Python)
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    
    # Thêm trường exp vào Payload
    to_encode.update({"exp": expire})
    
    # Ký và tạo token
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt

def decode_access_token(token: str) -> dict:
    """
    Giải mã và kiểm tra tính hợp lệ của JWT.
    """
    try:
        # Giải mã token, hàm này sẽ tự động kiểm tra chữ ký (Signature) và thời gian hết hạn (exp)
        decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return decoded_payload
    except jwt.ExpiredSignatureError:
        raise Exception("Lỗi: Token đã hết hạn (ExpiredSignatureError).")
    except jwt.InvalidSignatureError:
        raise Exception("Lỗi: Chữ ký của token không hợp lệ (InvalidSignatureError).")
    except jwt.InvalidTokenError:
        raise Exception("Lỗi: Token không hợp lệ hoặc bị định dạng sai (InvalidTokenError).")

# ==========================================
# KIỂM THỬ (TESTING)
# ==========================================
if __name__ == "__main__":
    # 1. Tạo token với thời gian hết hạn 30 phút
    token = create_access_token(
        data={
            "sub": "student01@gmail.com",
            "user_id": 1,
            "role": "student"
        },
        expires_minutes=30
    )
    
    print("=== TOKEN ĐƯỢC TẠO RA ===")
    print(token)
    print("\n=== KẾT QUẢ GIẢI MÃ HỢP LỆ ===")
    
    # 2. Giải mã token hợp lệ
    decoded_data = decode_access_token(token)
    print(decoded_data)
    
    # 3. Thử nghiệm với token bị sửa đổi (để kiểm chứng ngoại lệ)
    # Lấy token gốc, tách các phần và thử đổi "student" thành "admin" (giả lập)
    print("\n=== KIỂM THỬ VỚI TOKEN BỊ SỬA ĐỔI HOẶC HẾT HẠN ===")
    invalid_token = token + "make_it_invalid"
    try:
        decode_access_token(invalid_token)
    except Exception as e:
        print(e)
