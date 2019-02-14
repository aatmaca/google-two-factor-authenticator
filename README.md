# Google Authenticator
Two-factor authentication.

1. Signup endpoint.
Payload: username, password

2. Login endpoint
Payload: username, password
Response Headers: Token

3. Logout endpoint

4. Get profile endpoint
Verify user using the token provided in the Authorization header of the request

5. Configure MFA endpoint
Multi Factor Authorization using Google Authenticator which is accessible after login.

6. Verify Google Auth code endpoint
Ask user for Google Auth code and verify if it is correct. In the response of verify code endpoint you should provide new token that user can use to call get profile endpoint. The token received after login will no longer remain valid. 

Mux Router (https://github.com/gorilla/mux)
mgo Package (https://gopkg.in/mgo.v2)
Multi Factor Authorization https://github.com/sec51/twofactor
MongoDB
