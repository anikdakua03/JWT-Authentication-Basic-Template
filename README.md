b# JWT-Authentication-Basic-Template For .NET Web API
It is a template for JWT authentication setup for Dotnet web application using ASP.NET Identity

## Features included in this project : 
1. Uses basic JWT authentication with swagger configuration
2. Authorization in Swagger UI with bearer token
3. Verification and confirmation of email from user
4. Refreshing tokens in some certain time
5. Sending email ability to user using SMTP
6. Forgot/reset password via mail 
- When user is resetting their password , they must know their old password.
7. Added **Custom Signout** functionality
- Added one column in refresh token database as signed in or not 
- This will ensure the users is logged in or not.
- While user signs out this will update as false.
- After user is Signed out , no one can access those endpoints
- For accessing endpoints , it needs users email, valid token and other information .
8. Updated the login functionality
- An user with two factor authentication enbled will have to login via two factor code sent to the email
- An user without can twi factor enabled logs in normally.
> **Note:** Apply migrations and update the database to view in databse
</br>

> **Note:** I tried to apply all the basic functionality all from backend only.

### Current issues :
* Custom logout functionality , has some difficulties here, so it needs to check.
* Because an user can have many refresh tokens , so when checking user with userid , it may get wrong status.
* GetSesssionInfo is not properly done yet.
* Different JWT token but both user can access the items, both user have different token also , but still from other users's jwt token another user able to get items !!!!

* Setting up two factor authentication functionality is remaining.