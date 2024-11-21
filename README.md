
![AuthSphere_resize](https://github.com/user-attachments/assets/561999f8-aca5-478b-9b21-be95fb0e87dc)

<br>

Welcome to **AuthSphere!** This backend application offers a comprehensive solution for managing **user authentication and authorization** using modern technologies like **FastAPI, JWT tokens, and MariaDB**.

Designed with **Role-Based Access Control (RBAC)**, AuthSphere is perfect for small to medium-scale applications that require secure login, role-specific permissions, and efficient token management. The application also supports **multi-factor authentication (MFA)**, enhancing security by requiring additional verification steps for user access.

## 🚀 New Updates

**🛠️ Continuous Integration (CI) Pipeline**

AuthSphere now features an integrated CI pipeline powered by GitHub Actions to streamline testing and deployment processes:

Automated Testing: Every commit and pull request triggers the pipeline to ensure all tests pass, maintaining high-quality code.
Code Coverage: The pipeline ensures that the codebase is robust across various test scenarios.
Seamless Development: Contributors get real-time feedback on their changes, enhancing productivity.

🌟 Benefits of CI Integration:

- Improved Reliability: Each change undergoes rigorous testing before merging to reduce bugs in production.

- Efficient Collaboration: Developers receive automated feedback on commits, fostering a faster and collaborative workflow.

- Faster Releases: Automation reduces manual testing time, speeding up deployment cycles.
<br>

**🔐 Role-Based Access Control (RBAC)**
Our API supports Role-Based Access Control (RBAC) to manage permissions effectively and restrict access based on user roles. This functionality allows us to define various levels of access for different user types, such as admin, user, and other custom roles. ⚙️

   **🎯 How It Works**
   - Roles: Each user is assigned a specific role upon registration or through admin settings.
   - Permissions: Based on the role, users gain or are restricted from access to certain endpoints.
   - Role Verification: Using JWT tokens, the user's role is verified upon each request to ensure they have the appropriate permissions for the resource they're accessing.

   **🛡️ Key Role-Based Endpoints**
   - Protected Route - PUT /update_twofa/: To update the twoFA state, Accessible to authenticated users only.
   - Admin Only Route - PUT /assign-role/: Only accessible to users with the admin role.
   - OTP Verification - POST /verify_otp/: Validates OTP and returns the access_token.

**This project is continuously evolving, with future enhancements planned, including caching to further optimize performance.**

## 📈 Scalability

AuthSphere is designed with scalability in mind, ensuring that it can grow alongside your application needs. Here are some key aspects of its scalability:

- **Modular Architecture**: The application structure allows for easy integration of new features and authentication methods without major overhauls. This modularity facilitates smooth updates and enhancements as user requirements evolve.

- **Support for Multiple Authentication Methods**: AuthSphere can accommodate various authentication methods, including traditional email/password logins, OAuth providers (like Google), and future methods as they become available. This flexibility allows users to choose their preferred authentication method.

- **Performance Optimization**: With planned enhancements such as caching and optimized token management, AuthSphere aims to maintain high performance even as user loads increase. Efficient handling of user sessions and token validation helps ensure responsive interactions.

- **User Growth**: As your user base expands, AuthSphere can scale to support a growing number of simultaneous authentication requests. The underlying technologies, like FastAPI and MariaDB, are chosen for their ability to handle increased traffic effectively.

- **Future-Proofing**: By staying adaptable and open to new authentication technologies, AuthSphere ensures that your application remains relevant and secure in an ever-evolving tech landscape.


## 📖 Table of Contents
- [Features](#features)
- [Tech Stack](#%EF%B8%8Ftech-stack)
- [Installation](#installation)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Future Enhancements](#future-enhancements)
- [Showcase Your Skills](#showcase-your-skills)


## ✨Features
- **User Registration**: Secure user registration process.
- **JWT Authentication**: Token-based authentication for user sessions.
- **Role-Based Access Control (RBAC)**: Fine-grained access management.
- **Token Management**: Efficient handling of token lifecycle.

## 🛠️Tech Stack
- **Python**: Core programming language
- **FastAPI**: API framework for speed and flexibility
- **MariaDB**: Database for storing user data and token blacklist
- **JWT & JOSE**: Libraries for secure token generation and verification
- **dotenv**: For environment variable management


## 🚀Installation
1. **Clone the repository**:
    `git clone https://github.com/Shashank-Ganesh-Holla/AuthSphere.git`
2. **Navigate to the project directory**:
   `cd AuthSphere`
3. **Set up a virtual environment**:
   
   `python3 -m venv env` # For Windows(replace python3 as python)
   
   `source env/bin/activate`  # For Windows: env\Scripts\activate
5. **Install dependencies**:
  `pip install -r requirements.txt`
6. **Configure environment variables**:
   - You should hardcode the following values directly within your application or manage them through

     another secure method (such as environment variables set via your hosting or CI/CD process).
     
     `SECRET_KEY=your_secret_key`,
     
      `ALGORITHM=<any encryption algorithm of your choice ex: HS256>`,
     
      `ACCESS_TOKEN_EXPIRE_MINUTES=<time duration in minutes ex: 30>`
     <br>

       **SECRET_KEY: A secure, randomly generated string to sign your JWTs.**
     
       **ALGORITHM: The cryptographic algorithm used for token signing (e.g., HS256).**
     
7. **Set up the database**:
   Run the provided SQL scripts to create the necessary tables.
   - Navigate into the `auth_app` directory:
   - Run the schema.sql script to create the database and necessary tables.
   
## 🧑‍💻Usage: 
   - Navigate into the `auth_app` directory:
     ```bash
     cd auth_app
     ```
   - Start the server with:
     ```bash
     uvicorn main:app --reload
     ```
   - Explore API docs:
     - FastAPI provides interactive API docs at http://127.0.0.1:8000/docs 🌐

## 🔗API Endpoints:
Here’s a list of the main endpoints for this project:

- POST /register - Register a new user
- POST /login - Log in with credentials to receive a JWT
- POST /verify_otp/ - Verifies OTP received from login endpoint for twoFactor auth enabled user and returns JWT
- POST /logout - Log out a user, blacklisting the token (requires authentication)
- DELETE /delete_user/ - Delete a user account (requires authentication)
- GET /get-user-details/ - Fetch user information (requires authentication)
- GET /users/me/ - Fetch user from the input bearer token (requires authentication)
- PUT /assign-role/ - assign the role to the user (this is accessible only by an admin user) (requires authentication)
- PUT /update-twofa/ - updates the twoFA for the current user (requires authentication)


## 🌱Future Enhancements 
This project is continuously evolving, with plans to add caching and improve performance.

## 🏆Showcase Your Skills
This project is a fantastic showcase of your skills in backend development, security practices, and database management! Whether you're building more features or deploying it, feel free to customize it as needed for your portfolio!
