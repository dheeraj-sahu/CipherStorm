from fastapi import Request

def get_current_user(request: Request):
    return request.cookies.get("user")
