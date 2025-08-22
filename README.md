# DSİ Depo Management System

This project is a web-based inventory and request management system designed for managing items, requests, and personnel in an organization. It is built using Flask, MySQL, and Bootstrap.

## Features

- **User Authentication**: Login and registration functionality with role-based access control.
- **Inventory Management**: Admins and IT managers can view and manage the inventory.
- **Request Management**: Personnel and managers can request items, and managers/IT can approve or reject requests.
- **Item Assignment**: Approved items are assigned to personnel and can be transferred back to the inventory.
- **Role-Based Access**:
  - **Admin**: Full access to all features.
  - **Bilgi Müdür**: Manage IT-related requests and inventory.
  - **Şube Müdürü**: Approve/reject requests from their branch.
  - **Personel**: Request items and view assigned items.

## Technologies Used

- **Backend**: Flask (Python)
- **Frontend**: HTML, CSS, Bootstrap
- **Database**: MySQL
- **Authentication**: Flask-Login, Flask-Bcrypt

## Setup Instructions

Follow these steps to set up the project:

### 1. Clone the Repository
```bash
git clone https://github.com/b2230356015/DSIStorage.git
cd DSIStorage
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Database
Create a MySQL database and run the following SQL commands to create the necessary tables. Then you can adjust the table names and fields as needed.

```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    surname VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'Bilgi Müdür', 'Şube Müdürü', 'Personel') NOT NULL,
    sube VARCHAR(255)
);

CREATE TABLE requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    requester_id INT NOT NULL,
    item_name VARCHAR(255) NOT NULL,
    reason TEXT NOT NULL,
    sube VARCHAR(255),
    status ENUM('pending', 'pending_it', 'approved', 'rejected') DEFAULT 'pending',
    manager_comment TEXT,
    it_comment TEXT,
    FOREIGN KEY (requester_id) REFERENCES users(id)
);

CREATE TABLE items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    amount INT NOT NULL
);

CREATE TABLE personel_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    personel_id INT NOT NULL,
    item_name VARCHAR(255) NOT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (personel_id) REFERENCES users(id)
);
```

### 4. Create .env File
Create a `.env` file in the root directory of the project with the following content:
```plaintext
DB_HOST=127.0.0.1
DB_USER=<your_mysql_user>
DB_PASSWORD=<your_mysql_password>
DB_NAME=<your_database_name>
```

### 5. Start the Application
Make sure you have the MySQL server running and then start the Flask application. The application will be available at http://127.0.0.1:5000 :
```bash
python main.py
```