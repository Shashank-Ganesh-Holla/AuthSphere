AuthSphere: 🚀 Authentication & Authorization API
====================================================================

Welcome to **AuthSphere**, This backend application offers a comprehensive solution for managing user authentication and authorization using modern technologies like FastAPI, JWT tokens, and MariaDB.

Designed with Role-Based Access Control (RBAC), AuthSphere is perfect for small to medium-scale applications that require secure login, role-specific permissions, and efficient token management. This project is continuously evolving, with future enhancements planned, including caching to further optimize performance.

## Features
- **User Registration**: Secure user registration process.
- **JWT Authentication**: Token-based authentication for user sessions.
- **Role-Based Access Control (RBAC)**: Fine-grained access management.
- **Token Management**: Efficient handling of token lifecycle.


## Getting Started
1. **Clone the repository**: `git clone https://github.com/Shashank-Ganesh-Holla/AuthSphere.git`
2. **Install dependencies**: `pip install -r requirements.txt`
3. **Set up the database**: Run the provided SQL scripts to create the necessary tables.
4. **Run the application**: 
   - Navigate into the `auth_app` directory:
     ```bash
     cd auth_app
     ```
   - Start the server with:
     ```bash
     uvicorn main:app --reload

## Future Enhancements
This project is continuously evolving, with plans to add caching and improve performance.
