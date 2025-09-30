# Demo2-AuthToken

Demo2-AuthToken is a Python FastAPI demo project that shows how to create an OAuth2-style bearer token from a username and password, then use that token to authenticate requests to protected routes.

## Installation

Install the required dependencies using:

```bash
pip install -r requirements.txt
```

## Running the Project

Start the FastAPI server with:

```bash
uvicorn main:app --reload
```

The API will be available at `http://127.0.0.1:8000`.\
The interactive docs page will be available at `http://127.0.0.1:8000/docs`.

## Endpoints

- `POST /token`\
  Exchange username and password for a short-lived bearer token (JWT).

- `GET /me`\
  Returns the current user’s information. Requires an `Authorization: Bearer <token>` header.

- `GET /public`\
  A public route that requires no authentication.

- `GET /admin`\
  Example of a role-protected route. Requires the user to have the `editor` role.

## Example Requests

### Get a Token

```bash
curl -X POST http://127.0.0.1:8000/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=jane&password=janepword"
```

Example Response:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

### Use the Token

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=jane&password=janepword" | python -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

curl http://127.0.0.1:8000/me -H "Authorization: Bearer $TOKEN"
```

Example Response:

```json
{
  "username": "jane",
  "full_name": "Jane Doe",
  "roles": ["demo", "reader"]
}
```

---

⚠️ **Note**: For simplicity, this demo uses hard-coded plaintext passwords.\
In a real application, always hash passwords and use HTTPS.

