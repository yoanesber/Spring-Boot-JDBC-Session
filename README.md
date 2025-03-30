# Spring Web Application with JDBC Session

## 📖Overview
This project is a Spring web application demonstrating form-based authentication with JDBC Session. User sessions are stored in a PostgreSQL database. The application implements user authentication, password management, and account security features.
Additionally, this project uses **SB Admin Bootstrap Template** for the frontend UI, enhancing the user experience with a modern, responsive design.

### 🗄️Using Session JDBC
Spring Session JDBC is used to persist user session data in the PostgreSQL database instead of storing it in memory. This allows sessions to be retained across application restarts, improving scalability and reliability. Key advantages include:
- **Session Persistence**: Users remain logged in even if the application restarts.
- **Centralized Session Management**: All active sessions are stored in the database, making it easier to track and manage.
- **Security**: Protects against session hijacking by storing session attributes securely in the database
- **Scalability**: Suitable for distributed applications where multiple instances of the app need shared session access.


### 🚀Features
- ✅ **User Authentication**: Authentication is handled using `DaoAuthenticationProvider`, which loads user details from the database via `UserDetailsService` and verifies passwords using `PasswordEncoder`.
- ✅ **JDBC Session Management**: User session data is stored in a **PostgreSQL** database.
- ✅ **Force Password Change**: First-time users must change their password before accessing the portal.
- ✅ **Account Locking**: Accounts are locked after `n` consecutive failed login attempts due to bad credentials.
- ✅ **Thymeleaf Integration**: The frontend is built using **Thymeleaf** for **server-side rendering**.
- ✅ **Dashboard**: Authenticated users are redirected to a dashboard after a successful login.
- ✅ **CSRF Protection**: CSRF tokens are stored in `HttpSession` to prevent **cross-site request forgery** attacks.
- ✅ **Strict Content Security Policy (CSP)**: Enforces a strict content security policy to mitigate **XSS** attacks.

### 🔐Authentication Flow
1. Users log in via the login form.
2. Credentials are verified using `DaoAuthenticationProvider`.
3. On first login, users are forced to change their password.
4. After authentication, users are redirected to the dashboard.
5. After `n` failed login attempts, the account is locked.
---

## 🤖Tech Stack
The technology used in this project are:
- `Spring Boot Starter Web` – Provides essential components for building web applications, including an embedded web server and RESTful API support.
- `Spring Security` – Provides authentication and authorization mechanisms, ensuring secure access to the application.
- `Spring Session JDBC` – Manages user sessions in the PostgreSQL database, allowing session persistence across application restarts.
- `PostgreSQL` – A powerful, open-source relational database management system used to store user data and session information.
- `Hibernate` – A powerful ORM (Object-Relational Mapping) framework that simplifies database interactions by mapping Java objects to database tables.
- `Thymeleaf` – A Java-based templating engine that integrates with Spring Boot to render dynamic HTML views securely.
- `Lombok` – Reducing boilerplate code
---

## 🏗️Project Structure
The project is organized into the following package structure:
```bash
form-auth-demo/
│── src/main/java/com/yoanesber/form_auth_demo/
│   ├── 📂config/       # Contains JDBC session configuration and security settings
│   ├── 📂controller/   # Handles user authentication, password change requests, and custom error responses
│   ├── 📂dto/          # Data Transfer Object for password change requests
│   ├── 📂entity/       # Represents the user entity, user roles, and implements UserDetails for authentication
│   ├── 📂handler/      # Handles failed login attempts, including account locking, successful logins, and user logout events
│   ├── 📂repository/   # Interface for database access related to user management
│   ├── 📂service/      # Business logic layer
│   │   ├── 📂impl/     # Implementation of services
```
---

## ⚙Environment Configuration
Configuration values are stored in `.env.development` and referenced in `application.properties`.

Example `.env.development` file content:
```properties
# Application properties
APP_PORT=8081
SPRING_PROFILES_ACTIVE=development
WHITELABEL_ENABLED=false
SERVER_ERROR_PATH=/error

# Database properties
SPRING_DATASOURCE_PORT=5432
SPRING_DATASOURCE_USERNAME=your_username
SPRING_DATASOURCE_PASSWORD=your_password
SPRING_DATASOURCE_DB=your_db
SPRING_DATASOURCE_SCHEMA=your_schema

# Security properties
MAX_ATTEMPT_LOGIN=3
CSRF_REPOSITORY_NAME=CSRF_TOKEN
PERMIT_ALL_REQUEST_URL=/,/login,/css/**,/js/**,/fonts/**,/images/**,/scss/**,/vendor/**
PERMIT_ADMIN_REQUEST_URL=/admin/**
PERMIT_USER_REQUEST_URL=/user/**
PERMIT_API_REQUEST_URL=/api/**
PERMIT_STATIC_REQUEST_URL=/static/**
CSRF_IGNORED_REQUEST_URL=/login

# Login & logout properties
LOGIN_URL=/login
LOGIN_SUCCESS_URL=/dashboard
LOGOUT_URL=/perform-logout
LOGOUT_SUCCESS_URL=/login?logout

# Error page properties
ERROR_PAGE_403=error/403
ERROR_PAGE_404=error/404
ERROR_PAGE_415=error/415
ERROR_PAGE_500=error/500
```

Example `application.properties` file content:
```properties
# Application properties
spring.application.name=form-auth-demo
spring.profiles.active=${SPRING_PROFILES_ACTIVE}
server.port=${APP_PORT}
server.error.whitelabel.enabled=${WHITELABEL_ENABLED}
server.error.path=${SERVER_ERROR_PATH}

# Database properties
spring.datasource.url=jdbc:postgresql://localhost:${SPRING_DATASOURCE_PORT}/${SPRING_DATASOURCE_DB}?currentSchema=${SPRING_DATASOURCE_SCHEMA}
spring.datasource.username=${SPRING_DATASOURCE_USERNAME}
spring.datasource.password=${SPRING_DATASOURCE_PASSWORD}

# Enable JDBC Session Storage
spring.session.store-type=jdbc
spring.session.jdbc.initialize-schema=always

# Security properties
max-attempt-login=${MAX_ATTEMPT_LOGIN}
csrf-repository-name=${CSRF_REPOSITORY_NAME}
permit-all-request-url=${PERMIT_ALL_REQUEST_URL}
permit-admin-request-url=${PERMIT_ADMIN_REQUEST_URL}
permit-user-request-url=${PERMIT_USER_REQUEST_URL}
permit-api-request-url=${PERMIT_API_REQUEST_URL}
permit-static-request-url=${PERMIT_STATIC_REQUEST_URL}
csrf-ignored-request-url=${CSRF_IGNORED_REQUEST_URL}

# Login & logout properties
login-url=${LOGIN_URL}
login-success-url=${LOGIN_SUCCESS_URL}
logout-url=${LOGOUT_URL}
logout-success-url=${LOGOUT_SUCCESS_URL}

# Error page properties
error-page-403=${ERROR_PAGE_403}
error-page-404=${ERROR_PAGE_404}
error-page-415=${ERROR_PAGE_415}
error-page-500=${ERROR_PAGE_500}

# Thymeleaf properties
spring.thymeleaf.mode=HTML
spring.thymeleaf.encoding=UTF-8
spring.thymeleaf.cache=false
spring.thymeleaf.prefix=classpath:/templates/
```
---

## 💾 Database Schema (DDL – PostgreSQL)
The following is the database schema for the PostgreSQL database used in this project:

```sql
CREATE SCHEMA your_schema;

-- create table roles
CREATE TABLE IF NOT EXISTS your_schema.roles
(
	id integer NOT NULL GENERATED BY DEFAULT AS IDENTITY ( INCREMENT 1 START 1 MINVALUE 1 MAXVALUE 2147483647 CACHE 1 ),
	name character varying(20) COLLATE pg_catalog."default" NOT NULL,
	CONSTRAINT roles_pkey PRIMARY KEY (id)
);

-- feed data roles
INSERT INTO your_schema.roles ("name") VALUES
	 ('ROLE_USER'),
	 ('ROLE_MODERATOR'),
	 ('ROLE_ADMIN');


-- create table users
CREATE TABLE IF NOT EXISTS your_schema.users
(
	id bigint NOT NULL GENERATED BY DEFAULT AS IDENTITY ( INCREMENT 1 START 1 MINVALUE 1 MAXVALUE 9223372036854775807 CACHE 1 ),
	username character varying(20) COLLATE pg_catalog."default" NOT NULL,
    password character varying(150) COLLATE pg_catalog."default" NOT NULL,
    email character varying(100) COLLATE pg_catalog."default" NOT NULL,
    firstname character varying(20) COLLATE pg_catalog."default" NOT NULL,
    lastname character varying(20) COLLATE pg_catalog."default",
    is_enabled boolean NOT NULL DEFAULT false,
    is_account_non_expired boolean NOT NULL DEFAULT false,
    is_account_non_locked boolean NOT NULL DEFAULT false,
    is_credentials_non_expired boolean NOT NULL DEFAULT false,
    is_deleted boolean NOT NULL DEFAULT false,
	account_expiration_date timestamp with time zone,
    credentials_expiration_date timestamp with time zone,
	last_login timestamp with time zone,
	user_type character varying(15) COLLATE pg_catalog."default" NOT NULL,
	created_by character varying(20) NOT NULL,
	created_date timestamp with time zone NOT NULL DEFAULT now(),
	updated_by character varying(20) NOT NULL,
	updated_date timestamp with time zone NOT NULL DEFAULT now(),
	CONSTRAINT users_pkey PRIMARY KEY (id),
	CONSTRAINT users_unique_username UNIQUE (username),
	CONSTRAINT users_unique_email UNIQUE (email),
	CONSTRAINT users_user_type_check CHECK (user_type::text = ANY (ARRAY['SERVICE_ACCOUNT'::character varying, 'USER_ACCOUNT'::character varying]::text[]))
);

-- feed data users
-- both superadmin and channel1 password is `P@ssw0rd`
INSERT INTO your_schema.users (username,"password",email,firstname,lastname,is_enabled,is_account_non_expired,is_account_non_locked,is_credentials_non_expired,is_deleted,account_expiration_date,credentials_expiration_date,last_login,user_type,created_by,created_date,updated_by,updated_date) VALUES
	 ('superadmin','$2a$10$71wrLlzlkJ/54ZWDwA6KiegFX0naXg.T2zvKB2EbyqdS1Yl7Cwt1W','superadmin@youremail.com','Super','Admin',true,true,true,true,false,'2025-04-23 21:52:38+07','2025-02-28 01:58:35.835127+07','2025-02-11 22:54:32.816+07','USER_ACCOUNT','system','2024-09-04 03:42:58.847+07','system','2024-11-28 01:58:35.835+07'),
	 ('channel1','$2a$10$eP5Sddi7Q5Jv6seppeF93.XsWGY8r4PnsqprWGb5AxsZ9TpwULIGa','channel1@youremail.com','Channel','One',true,true,true,true,false,'2025-07-14 19:50:56.880054+07','2025-05-11 22:57:25.611336+07','2025-02-10 14:53:04.704+07','SERVICE_ACCOUNT','superadmin','2024-09-04 03:44:48.827+07','superadmin','2025-02-11 22:57:25.609+07');

-- create table user_roles
CREATE TABLE IF NOT EXISTS your_schema.user_roles
(
    user_id bigint NOT NULL,
    role_id integer NOT NULL,
    CONSTRAINT user_roles_pkey PRIMARY KEY (user_id, role_id),
    CONSTRAINT user_roles_fkey1 FOREIGN KEY (role_id)
        REFERENCES roles (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION,
    CONSTRAINT user_roles_fkey2 FOREIGN KEY (user_id)
        REFERENCES users (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
);

-- feed data user_roles
INSERT INTO your_schema.user_roles (user_id,role_id) VALUES
	 (1,1),
	 (1,2),
	 (1,3),
	 (2,3);


-- create table spring_session
CREATE TABLE IF NOT EXISTS your_schema.spring_session (
    primary_id character(36) COLLATE pg_catalog."default" NOT NULL,
    session_id character(36) COLLATE pg_catalog."default" NOT NULL,
    creation_time bigint NOT NULL,
    last_access_time bigint NOT NULL,
    max_inactive_interval integer NOT NULL,
    expiry_time bigint NOT NULL,
    principal_name character varying(100) COLLATE pg_catalog."default",
    CONSTRAINT spring_session_pk PRIMARY KEY (primary_id)
);

CREATE UNIQUE INDEX spring_session_idx1 ON your_schema.spring_session USING btree (session_id);
CREATE INDEX spring_session_idx2 ON your_schema.spring_session USING btree (expiry_time);
CREATE INDEX spring_session_idx3 ON your_schema.spring_session USING btree (principal_name);

-- create table spring_session_attributes
CREATE TABLE IF NOT EXISTS your_schema.spring_session_attributes (
    session_primary_id character(36) COLLATE pg_catalog."default" NOT NULL,
    attribute_name character varying(200) COLLATE pg_catalog."default" NOT NULL,
    attribute_bytes bytea NOT NULL,
    CONSTRAINT spring_session_attributes_pk PRIMARY KEY (session_primary_id, attribute_name),
    CONSTRAINT spring_session_attributes_fk FOREIGN KEY (session_primary_id)
        REFERENCES your_schema.spring_session (primary_id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
);

```
---

## 🛠️Installation & Setup
A step by step series of examples that tell you how to get a development env running.

1. Ensure you have **Git installed on your Windows** machine, then clone the repository to your local environment:
```bash
git clone https://github.com/yoanesber/Spring-Boot-JDBC-Session.git
cd Spring-Boot-JDBC-Session
```

2. Set up PostgreSQL
- Run the provided DDL script to set up the database schema
- Configure the connection in .env.development file:
```properties
# Database properties
SPRING_DATASOURCE_PORT=5432
SPRING_DATASOURCE_USERNAME=your_username
SPRING_DATASOURCE_PASSWORD=your_password
SPRING_DATASOURCE_DB=your_db
SPRING_DATASOURCE_SCHEMA=your_schema
```

3. Configure Login Attempt Limit
Set the `MAX_ATTEMPT_LOGIN` value in `.env.development` to define the number of failed login attempts before an account is locked. This helps in testing without waiting too long.
```properties
# Security properties
MAX_ATTEMPT_LOGIN=3
```

3. Run the application locally:
Make sure PostgreSQL is running, then execute:
```bash
mvn spring-boot:run
```

4. Now, application is available at:
```bash
http://localhost:8081/
```

---

## 🧪Testing Scenarios
1. Test Account Locking
When a user enters incorrect login credentials, the system displays an error message indicating invalid username or password.

![Invalid username or password](https://github.com/user-attachments/assets/d4d29ed1-66c2-4cf4-909b-a381663ce741)

If a user repeatedly enters incorrect credentials beyond the allowed limit (`MAX_ATTEMPT_LOGIN`), the system locks the account.

![User account is locked](https://github.com/user-attachments/assets/0b0fd5d3-844d-4b29-8503-69f9ffff75ff)

Once the failed login attempts reach the limit (`MAX_ATTEMPT_LOGIN`), the system will automatically set `is_account_non_locked = false` in the database, preventing further login attempts. 

![is_account_non_locked is false](https://github.com/user-attachments/assets/961b7c8c-ac42-4d2a-9ccb-de8e4db52e26)

**Note**: To unlock an account, you can manually update the user record in PostgreSQL by resetting the `is_account_non_locked` field to `true`.

2. Test authentication failure responses for:
- **Disabled User Attempting Login**
If a user account is disabled (i.e., `is_enabled = false` in the database), any login attempt will be rejected. The system displays a message indicating that the account is disabled, preventing the user from accessing the portal until an administrator reactivates the account.

![Manually update is_enabled to false](https://github.com/user-attachments/assets/f8215e8f-34d5-439c-98c9-506f6fd6811b)

![User is disabled](https://github.com/user-attachments/assets/4a12354b-329c-4b7f-a70d-acca22c30c10)

- **Expired Credentials Attempting Login**
If a user’s credentials have expired (`is_credentials_non_expired = false` in the database), the system prevents authentication and prompts the user to update their password. This ensures that old or potentially compromised credentials are not used indefinitely.  
![Manually update is_credentials_non_expired to false](https://github.com/user-attachments/assets/41769866-9298-4b73-a209-c9eaf88e9c2c)  
![User credentials have expired](https://github.com/user-attachments/assets/ac76e1c1-3daa-482b-91ec-1474c7b20250)  

- **Expired Account Attempting Login**
If an account has expired (`is_account_non_expired = false` in the database), the user will be unable to log in, and the system will notify them that their account is no longer valid. Administrators may extend the account expiration date to restore access.  
![Manually update is_account_non_expired to false](https://github.com/user-attachments/assets/68b82110-4b66-4104-99af-2bfc66ee6b05)  
![User account has expired](https://github.com/user-attachments/assets/704498de-f892-48e5-bb85-8e5dab598822)  

3. Reset Last Login
Set `last_login` to `NULL` in the database.  
![Manually update last_login to NULL](https://github.com/user-attachments/assets/d4b35bc4-18d8-43f7-a91b-fe3c2801f40f)  

`Re-login` and confirm that the system redirects to the force password change page.  
![Force password change page](https://github.com/user-attachments/assets/26b90af2-e7d5-4bae-bcf5-75d5ec5fc2eb)  

4. Test Force Password Change Validation
Submit the password change form with mismatched `new password` and `confirm password` fields to trigger validation errors.  
![New password and confirm password do not match](https://github.com/user-attachments/assets/6f96d075-0d10-41f8-b707-ecf951ddc7dc)  

Submit a valid and correctly matched `new password` and `confirm password` to successfully update the password  
![Password changed successfully](https://github.com/user-attachments/assets/0f100b2c-916b-4ff6-81a5-71d1e2816d37)  

5. Test CSRF Protection
- Remove the CSRF token via browser inspect element.  
![Delete element - csrf](https://github.com/user-attachments/assets/1aa5ff64-0ea3-4d94-a27f-8a1825e5bdc0)  

- Submit a valid password change request and verify that it is rejected with a 403 Forbidden response.  
![Force change password with no csrf response](https://github.com/user-attachments/assets/63dda5f6-484e-405b-9518-ab7adfa6216b)  

**Note**: If a user manually removes the CSRF token from the request (e.g., via browser developer tools), the system will detect the missing token and reject the request with a `403 Forbidden` error, ensuring protection against cross-site request forgery attacks.

6. Test Logout
- Logout from the application  
![Logout from the application](https://github.com/user-attachments/assets/bb73ad8c-600c-4351-a951-ba7cbe3b9b2c)  

**Note**: When a user logs out, their session is removed from the `spring_session` table in PostgreSQL. This ensures that logged-out users cannot reuse an old session to gain access.  

7. Test Successful Password Change and Re-login
Confirm that the force password change process is completed and the user is redirected to the dashboard.  
![Dashboard page](https://github.com/user-attachments/assets/2cd2d623-10bf-466f-8b31-c9d129aafc3e)  
![spring_session table](https://github.com/user-attachments/assets/92bd9ce9-584a-4afd-bf3c-438c82403b4c)  
![spring_session_attributes table](https://github.com/user-attachments/assets/4a653e83-b0e4-4cab-a109-1f9cd829949c)  

---

## 📝Notes & Future Enhancements
- **Admin User Management**: Implement an admin feature that allows managing user accounts, including unlocking locked accounts, extending credentials and account expiration, and enabling or disabling user access.
- **Active Session Monitoring**: Provide an admin panel to view active user sessions stored in the `spring_session` table. Admins should have the ability to terminate specific sessions to enforce security policies.
- **Automated Email Notifications**: Introduce an email notification service to inform users when their accounts are locked, passwords are changed, or their credentials/accounts are about to expire. This feature could be implemented using an asynchronous approach such as Redis (Publisher/Subscriber) or a scheduled task to send timely alerts.
- **Security Logs for Admins**: Implement a logging system that captures security-related events, such as failed login attempts, account locks, and session terminations. These logs should be accessible only to administrators for auditing and monitoring purposes.