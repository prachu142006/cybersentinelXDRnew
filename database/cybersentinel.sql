USE cybersentinel;

-- ============================================
-- USERS TABLE
-- ============================================

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(120) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    security_score INT DEFAULT 100,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- ADMINS TABLE
-- ============================================

CREATE TABLE admins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- LOGIN LOGS
-- ============================================

CREATE TABLE login_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('SUCCESS','FAILED') NOT NULL,

    CONSTRAINT fk_login_user
        FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);

-- ============================================
-- ATTACK LOGS
-- ============================================

CREATE TABLE attack_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    ip_address VARCHAR(45) NOT NULL,
    attack_type VARCHAR(100) NOT NULL,
    severity ENUM('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL,
    description TEXT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_attack_user
        FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE SET NULL
);

-- ============================================
-- BLOCKED IPS
-- ============================================

CREATE TABLE blocked_ips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    reason VARCHAR(255),
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- INCIDENTS
-- ============================================

CREATE TABLE incidents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    attack_log_id INT NOT NULL,
    incident_status ENUM('OPEN','INVESTIGATING','RESOLVED')
    DEFAULT 'OPEN',
    remarks TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_incident_attack
        FOREIGN KEY(attack_log_id)
        REFERENCES attack_logs(id)
        ON DELETE CASCADE
);

-- ============================================
-- SECURITY LOGS
-- ============================================

CREATE TABLE security_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    event VARCHAR(255) NOT NULL,
    threat_score INT DEFAULT 0,
    log_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_security_user
        FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE SET NULL
);

-- ============================================
-- INDEXES
-- ============================================

CREATE INDEX idx_users_email
ON users(email);

CREATE INDEX idx_login_logs_ip
ON login_logs(ip_address);

CREATE INDEX idx_attack_logs_ip
ON attack_logs(ip_address);

CREATE INDEX idx_security_logs_score
ON security_logs(threat_score);

INSERT INTO admins(username,password)
VALUES
(
'admin',
'$2b$12$REPLACE_WITH_BCRYPT_HASH'
);

INSERT INTO admins(username,password)
VALUES
(
'admin',
'$2b$12$sQ7P5sS65tqhgi.6podZbOQ5zVz7fypbKrN9S2CCpzFNnSuel5Tey'
);

SELECT * FROM admins;
DELETE FROM admins;
INSERT INTO admins (username, password)
VALUES (
'admin',
'$2b$12$sQ7P5sS65tqhgi.6podZbOQ5zVz7fypbKrN9S2CCpzFNnSuel5Tey'
);

SELECT * FROM login_logs;
DROP TABLE incidents;
CREATE TABLE incidents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) DEFAULT 'Open',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

SELECT * FROM login_logs;
SELECT * FROM attack_logs;
SELECT * FROM blocked_ips;
SELECT * FROM incidents;
ALTER TABLE login_logs
ADD COLUMN email VARCHAR(120);

ALTER TABLE login_logs
ADD COLUMN attempted_password VARCHAR(255);
SELECT * FROM attack_logs;