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
