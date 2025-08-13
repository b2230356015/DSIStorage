-- Create `users` table
CREATE TABLE users (
                       id INT AUTO_INCREMENT PRIMARY KEY,
                       name VARCHAR(100),
                       surname VARCHAR(100),
                       email VARCHAR(100) UNIQUE,
                       password_hash VARCHAR(255),
                       role ENUM('admin', 'Personel', 'Şube Müdürü', 'Bilgi Müdür'),
                       sube INT,
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create `items` table
CREATE TABLE items (
                       id INT AUTO_INCREMENT PRIMARY KEY,
                       name VARCHAR(100),
                       amount INT,
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create `requests` table
CREATE TABLE requests (
                          id INT AUTO_INCREMENT PRIMARY KEY,
                          requester_id INT,
                          item_name VARCHAR(100),
                          reason TEXT,
                          status ENUM('pending_manager', 'pending_it', 'approved', 'rejected') DEFAULT 'pending_manager',
                          manager_comment TEXT,
                          it_comment TEXT,
                          sube INT,
                          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                          FOREIGN KEY (requester_id) REFERENCES users(id)
);

-- Create `personel_items` table
CREATE TABLE personel_items (
                                id INT AUTO_INCREMENT PRIMARY KEY,
                                personel_id INT,
                                item_name VARCHAR(100),
                                assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                FOREIGN KEY (personel_id) REFERENCES users(id)
);