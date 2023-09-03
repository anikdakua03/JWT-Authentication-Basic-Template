b# JWT-Authentication-Basic-Template For .NET Web API
It is a template for JWT authentication setup for Dotnet web application using ASP.NET Identity

## Features included in this project : 
1. Uses basic JWT authentication with swagger configuration
2. Authorization in Swagger UI with bearer token
3. Verification and confirmation of email from user
4. Refreshing tokens in some certain time
5. Sending email ability to user using SMTP
6. Forgot/reset password via mail 
7. Added **Custom Signout** functionality
- Added one column in refresh token database as signed in or not 
- This will ensure the users is logged in or not.
- While user signs out this will update as false.
- After user is Signed out , no one can access those endpoints
- For accessing endpoints , it needs users email, valid token and other information .

> **Note:** Apply migrations and update the database to view in databse
</br>

> **Note:** I tried to apply all the basic functionality all from backend only.
