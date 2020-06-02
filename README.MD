<h1 align="center">
  Oauth2 Fake Server
</h1>
<h4 align="center">A simple Oauth2 authentication server with necessary endpoints for quick development and testing</h4>

<p align="center">
  <a href="#intro">Intro</a> •
  <a href="#features">Features</a> •
  <a href="#getting-started">Getting Started</a> •
  <a href="#setup">Setup</a> •
  <a href="#usage">Usage</a> •
  <a href="#license">License</a>
</p>

---
<p align="center">
<a href="https://discord.gg/fXPzq3a"><img src="https://img.shields.io/badge/chat-on%20discord-7289da.svg" alt="Chat"></a>
<img alt="GitHub" src="https://img.shields.io/github/license/pratyayrudra/oauth2-fake-server">
</p>

# Intro
> This is only for development purpose and not at all production ready

To work with some APIs and Services developers often need a Oauth2.0 authorization system that can generate Access Tokens, Refresh Tokens and also a way to verify those. 

There are several Oauth 2.0 providers that simplify the entire process of maintaining server, authentication, authorization and more in a secure way. But just for quick development/testing of small projects this systems can be very difficult to use and manage. So often false end points are created by developers to simulate the entire process. 

This Oauth2 Fake Server helps you to do that by creating a simple and standalone Oauth2.0 Server that follows the *Authorization Code Grant* flow. 
> Note: This server is not as secure and 100% compliant with Oauth2.0 guidelines.

# Features

- Authorization Code Grant flow of Oauth 2.0
 - Can generate *access token* and *refresh_token*
 - Can issue *access_token* using the *refresh_token*
 - Can validate User *email* and *password* to simulate authorization.
 - Can validate *access_token*
 - Can get userinfo using *access_token*
 - Can revoke both *access_token* and *refresh_token*

# Getting Started
To clone and run this application, you'll need [Git](https://git-scm.com/) and [Node.js](https://nodejs.org/en/download/) (which comes with [npm](http://npmjs.com/)) installed on your computer. From your command line:
```

# Clone this repository
$ git clone https://github.com/pratyayrudra/oauth2-fake-server.git

# Go into the repository
$ cd oauth2-fake-server

# Install dependencies
$ npm install

# Run the server
$ npm start

# Server started at http://localhost:3000

```

#  Setup
> You can use with default values and start testing the server with [POSTMAN](https://www.postman.com/)
### Environment Setup (Optional)
| **Variable**  | **Default Value**                  | *Customizable* |
| ------------- | ---------------------------------- | -------------- |
| PORT          | 3000                               | YES            |
| CLIENT_ID     | fakeclientid                       | YES            |
| CLIENT_SECRET | fakeclientsecret                   | YES            |
| REDIRECT_URI  | https://oauth.pstmn.io/v1/callback | YES            |
- The REDIRECT_URI is an array so if you need more than 1 *redirect_uri* keep adding them in array separated by a coma. 
- You can change this values in the **.env** file.
### User Credential Setup (Optional)

| **Field** | **Default Value**  | **Customizable** |
| --------- | ------------------ | ---------------- |
| email     | thor@asgard.marvel | YES              |
| password  | strongestavenger   | YES              |
- There is no signup method so only one user can be used at max.
- You can use the default user to test.
- The user credentials need to be manually entered into the **User.json** file.
- You can set the *Email* and *Password* to anything.

# Usage

### GET ``` /authorize ```
 - The client sends request here with :
	 - *client_id*
	 - *state*
	 - *redirect_uri*
- The server verifies the details.
- Redirects to login page where the user enters *Email* and *Password*.
- If user details and all parameters are correct then the server redirects to the *redirect_uri* along with **Authorization Code** .
```
GET /authorize HTTP/1.1
Host: localhost:3000
Content-Type: application/x-www-form-urlencoded

client_id=fakeclientid
&state=abcd1234
&redirect_uri=https://oauth.pstmn.io/v1/callback
```
### POST ``` /token ```
- The client send request here with :
	-	*client_id*
	-	*grant_type* ( authorization_code or refresh_token )
	-	*code* ( that was received in the previous step -> only if first time )
	-	*refresh_token* ( only if *access_token* needs to be refreshed )
- The server verifies the details.
- Return the generated tokens according to *grant_type* :
	-  authorization_code => 
		- new **access_token** ( signed JWT token with 24hrs validity )
		- new **refresh_token** ( long term validity )
	-  refresh_token =>
		- new **access_token** ( previous one is revoked )
```
POST /token HTTP/1.1
Host: localhost:3000
Content-Type: application/x-www-form-urlencoded

client_id=fakeclientid
&grant_type=authorization_code
&code=bc2c6f28f0gr
```
```
POST /token HTTP/1.1
Host: localhost:3000
Content-Type: application/x-www-form-urlencoded

client_id=fakeclientid
&grant_type=refresh_token
&refresh_token=69d8f97dffcababab21903b8419dc392bad1a021
```

### GET ```/userinfo```
-  ```Bearer <access_token>``` for authorization.
- The server responds with the User Info ( email only in this case ).
```
GET /userinfo HTTP/1.1
Host: localhost:3000
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyNTRhNWFjYWVlNDcyODExODUyOGNkMDk0MjRhNDRkOCIsImlhdCI6MTU5MTAzMzE1NiwiZXhwIjoxNTkxMTE5NTU2fQ.CB0Htndz6lqMdlB4nbCNiYwq1FL23Z_QSwLf3pONO1g
```

### POST ``` /revoke ```
- The client send here with :
	- *refresh_token*
- `Bearer <access_token>` for authorization.
- Server verifies and revokes both the *access_token* and *refresh_token*.
```
POST /revoke HTTP/1.1
Host: localhost:3000
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyNTRhNWFjYWVlNDcyODExODUyOGNkMDk0MjRhNDRkOCIsImlhdCI6MTU5MTAzMzE1NiwiZXhwIjoxNTkxMTE5NTU2fQ.CB0Htndz6lqMdlB4nbCNiYwq1FL23Z_QSwLf3pONO1g
Content-Type: application/x-www-form-urlencoded

refresh_token=69d8f97dffcababab21903b8419dc392bad1a021
```
# Roadmap
### List of things planned :
- User registration.
- Database integration.

# License
MIT