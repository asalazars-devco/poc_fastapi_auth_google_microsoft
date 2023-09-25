from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from datetime import timedelta, datetime
from jose import JWTError, jwt
import requests

## instalar python-multipart


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return "Hi from FastAPI"


### --------- POC AUTHORIZATION --------- ###

SECRET_KEY_TOKEN = "poc_authorization_secret_key"
ALGORITHM_TOKEN = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_db = [{"email": "asalazars@devco.com.co"}]

# Configurar el esquema de seguridad
oauth2_scheme = HTTPBearer()


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    data_to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    data_to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        data_to_encode, key=SECRET_KEY_TOKEN, algorithm=ALGORITHM_TOKEN
    )
    print(encoded_jwt)
    return encoded_jwt


# Función para verificar si el usuario tiene acceso
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(oauth2_scheme),
):
    # Verificar y decodificar el token Bearer aquí
    token = credentials.credentials
    try:
        data = jwt.decode(token, SECRET_KEY_TOKEN, algorithms=[ALGORITHM_TOKEN])

        print(data)

        for user in fake_db:
            if user["email"] == data["sub"]:
                return token
    except Exception as e:
        print(e)
        raise HTTPException(status_code=401, detail="No autorizado")


# Ruta protegida
@app.get("/private-info")
async def get_private_info(current_user: str = Depends(get_current_user)):
    print(current_user)
    # Esta ruta solo es accesible si el usuario tiene un token válido
    return {"message": "Esta es información privada"}


@app.post("/authenticate_google")
async def authenticate_with_google(request: dict):
    try:
        # print(request)

        # URL de la API de Google
        url = "https://www.googleapis.com/oauth2/v1/userinfo"

        # Token de portador (Bearer Token) que obtuviste previamente
        bearer_token = request["googleAccessToken"]

        # Configurar el encabezado de autorización con el token de portador
        headers = {"Authorization": f"Bearer {bearer_token}"}

        # Realizar la solicitud GET a la API
        response_google = requests.get(url, headers=headers)
        data_google = response_google.json()
        print(data_google)

        # Aquí puedes agregar lógica adicional, como verificar si el usuario ya existe en tu base de datos y crearlo si no lo hace.
        for user in fake_db:
            if user["email"] == data_google["email"]:
                # Crear un token de acceso propio en el backend y devolverlo
                access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
                access_token = create_access_token(
                    data={"sub": data_google["email"]},
                    expires_delta=access_token_expires,
                )

                return {"access_token": access_token, "token_type": "bearer"}
            return "User not found"

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Error authentication in server")


from msal.oauth2cli.oidc import decode_id_token


@app.post("/authenticate_microsoft")
async def authenticate_with_microsoft(request: dict):
    try:
        # Obtener data del token de Microsoft
        # token = request["microsoftIdToken"]

        # URL de la API de Microsoft
        # url = "https://graph.microsoft.com/v1.0/me"
        url = "https://graph.microsoft.com/oidc/userinfo"

        # Token de portador (Bearer Token) que obtuviste previamente
        access_token = request["microsoftAccessToken"]

        # Configurar el encabezado de autorización con el token de portador
        headers = {"Authorization": f"Bearer {access_token}"}

        # Realizar la solicitud GET a la API
        response_ms = requests.get(url, headers=headers)
        data_ms = response_ms.json()
        print(data_ms)

        # try:
        #     data = decode_id_token(
        #         id_token=token, client_id="29f88bff-ab05-4fe0-bbc8-808272f11348"
        #     )
        # except Exception as e:
        #     print(e)
        #     raise HTTPException(status_code=401, detail="No autorizado")

        # print("data: ", data)

        # # Aquí puedes agregar lógica adicional, como verificar si el usuario ya existe en tu base de datos y crearlo si no lo hace.
        # for user in fake_db:
        #     if user["email"] == data_google["email"]:
        #         # Crear un token de acceso propio en el backend y devolverlo
        #         access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        #         access_token = create_access_token(
        #             data={"sub": data_google["email"]},
        #             expires_delta=access_token_expires,
        #         )

        #         return {"access_token": access_token, "token_type": "bearer"}
        #     return "User not found"

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Error authentication in server")
