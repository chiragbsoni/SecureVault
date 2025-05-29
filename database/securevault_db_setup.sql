-- Step 1: Create the database
DROP DATABASE IF EXISTS securevault;
CREATE DATABASE securevault;
USE securevault;

-- Step 2: Create roles table
CREATE TABLE roles (
  role_id INT AUTO_INCREMENT PRIMARY KEY,
  role_name VARCHAR(20) UNIQUE NOT NULL
);

-- Step 3: Insert default roles
INSERT INTO roles (role_name) VALUES ('admin'), ('user');

-- Step 4: Create users table
CREATE TABLE users (
  user_id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  email VARCHAR(100) NOT NULL UNIQUE,
  mfa_secret VARCHAR(64),
  role_id INT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (role_id) REFERENCES roles(role_id)
);

-- Step 5: Create credentials table
CREATE TABLE credentials (
  cred_id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  website VARCHAR(100),
  login_username VARCHAR(100),
  encrypted_password VARBINARY(512),
  iv VARBINARY(16),
  notes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Step 6: Create activity logs table
CREATE TABLE activity_logs (
  log_id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  activity_type VARCHAR(50),
  ip_address VARCHAR(45),
  user_agent TEXT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(user_id)
);
