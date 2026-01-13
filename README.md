# User-authentication-system-Ecommerce-version-
DRF code on Complete User authentication System (Ecommerce version)

This repository contains a comprehensive user authentication and authorization system built with Django and Django Rest Framework (DRF). It is designed for an e-commerce platform, featuring a robust Role-Based Access Control (RBAC) system with distinct roles for Admin, Seller, and Customer.

## Features

*   **User Authentication:**
    *   User Registration with email verification.
    *   JWT-based login/logout functionality using `djangorestframework-simplejwt`.
    *   Access and Refresh token handling, including token rotation and blacklisting for enhanced security.
*   **Password Management:**
    *   Secure "Forgot Password" flow with token-based email reset.
    *   Endpoint for authenticated users to change their password.
*   **Role-Based Access Control (RBAC):**
    *   Pre-defined roles: `Admin`, `Seller`, `Customer`.
    *   Granular permissions system based on resource and action (e.g., `product_view`, `order_create`).
    *   Roles are associated with a set of permissions.
    *   Admin-only endpoints for managing users, roles, and permissions assignment.
*   **API Security:**
    *   Endpoint-specific rate limiting (throttling) to prevent abuse on registration, login, and password reset attempts.
*   **User Management:**
    *   Admins can list, create, retrieve, update, and delete users.
    *   Users can view their own profile information.
*   **Setup Command:**
    *   A custom management command (`setup_rbac`) to easily initialize the database with all necessary roles and permissions.

## Technology Stack

*   Python
*   Django
*   Django Rest Framework (DRF)
*   Simple JWT for DRF

## Getting Started

### Prerequisites

*   Python 3.8+
*   `pip` package manager

### Installation and Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/harbdulmarleyk03/user-authentication-system-ecommerce-version-.git
    cd user-authentication-system-ecommerce-version-/ecommerce
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    # For Unix/macOS
    python3 -m venv venv
    source venv/bin/activate

    # For Windows
    python -m venv venv
    .\venv\Scripts\activate
    ```

3.  **Install dependencies:**
    *(Note: A `requirements.txt` file is not included. Install the core packages below.)*
    ```bash
    pip install django djangorestframework djangorestframework-simplejwt
    ```

4.  **Configure Email Settings:**
    Open `ecommerce/ecommerce/settings.py` and update the following settings with your SMTP email provider's credentials. These are necessary for email verification and password resets.
    ```python
    EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
    EMAIL_HOST = "smtp.gmail.com"  # e.g., smtp.gmail.com
    EMAIL_USE_TLS = True
    EMAIL_PORT = 587
    EMAIL_HOST_USER = "your-email@example.com"
    EMAIL_HOST_PASSWORD = "your-email-app-password"
    ```

5.  **Apply database migrations:**
    ```bash
    python manage.py migrate
    ```

6.  **Set up Roles and Permissions:**
    Run the custom management command to populate the database with the initial RBAC configuration.
    ```bash
    python manage.py setup_rbac
    ```

7.  **Create a superuser (optional):**
    This allows access to the Django admin interface.
    ```bash
    python manage.py createsuperuser
    ```

8.  **Run the development server:**
    ```bash
    python manage.py runserver
    ```
    The API will be available at `http://127.0.0.1:8000/`.

## Management Command

This project includes a command to initialize the roles and permissions required for the application.

*   **`setup_rbac`**
    Creates the `Admin`, `Seller`, and `Customer` roles and defines permissions for managing users, products, orders, and categories. It then assigns the appropriate set of permissions to each role.
    ```bash
    python manage.py setup_rbac
    ```
    This command should be run once after the initial database migration.

## API Endpoints

All endpoints are prefixed with `/api`.

### Authentication & Authorization

| Method | Endpoint | Description | Access |
| :--- | :--- | :--- | :--- |
| `POST` | `/auth/register/` | Register a new user (as Customer or Seller). | Public |
| `POST` | `/auth/login/` | Log in to get access and refresh tokens. | Public |
| `POST` | `/auth/logout/` | Blacklists the refresh token to log the user out. | Authenticated |
| `GET` | `/auth/verify-email/<token>/` | Verify a user's email address using the token sent. | Public |
| `POST` | `/auth/password-reset/request/` | Request a password reset email. | Public |
| `POST` | `/auth/password-reset/confirm/` | Confirm password reset with a new password and token. | Public |
| `POST` | `/auth/change-password/` | Change password for the currently logged-in user. | Authenticated |
| `POST` | `/token/refresh/` | Obtain a new access token using a refresh token. | Public |

### User Management

| Method | Endpoint | Description | Access |
| :--- | :--- | :--- | :--- |
| `GET` | `/users/me/` | Get details of the currently authenticated user. | Authenticated |
| `GET`, `POST` | `/users/` | List all users or create a new user. | Admin Only |
| `GET`, `PUT`, `DELETE` | `/users/<id>/` | Retrieve, update, or delete a specific user. | Admin or Owner |

### Role & Permission Management (Admin Only)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET`, `POST` | `/roles/` | List all roles or create a new role. |
| `GET`, `PUT`, `DELETE` | `/roles/<id>/` | Retrieve, update, or delete a specific role. |
| `POST` | `/roles/<id>/assign/` | Assign a role to a user (`{ "user_id": <id> }`). |
| `POST` | `/roles/<id>/revoke/` | Revoke a role from a user (`{ "user_id": <id> }`). |
| `GET` | `/permissions/` | List all available permissions in the system. |
| `GET` | `/permissions/<id>/` | Retrieve details for a specific permission. |
