from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    model_config = ConfigDict(
        title="LoginRequest",
        json_schema_extra={
            "example": {
                "username": "demo-user",
                "password": "secret123",
            }
        },
    )

    username: str = Field(..., description="Имя пользователя, зарегистрированное в системе.")
    password: str = Field(..., description="Пароль пользователя для получения JWT-токена.")


class RegisterRequest(BaseModel):
    model_config = ConfigDict(
        title="RegisterRequest",
        json_schema_extra={
            "example": {
                "username": "demo-user",
                "password": "secret123",
                "email": "demo-user@example.com",
            }
        },
    )

    username: str = Field(..., description="Желаемое уникальное имя пользователя.")
    password: str = Field(..., description="Пароль нового пользователя.")
    email: str = Field(..., description="Уникальный email пользователя.")


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    role: str
