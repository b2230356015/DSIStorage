-- Insert sample data into `users`
INSERT INTO users (name, surname, email, password_hash, role, sube) VALUES
                                                                        ('Admin', 'User', 'admin@example.com', 'hashed_password', 'admin', NULL),
                                                                        ('John', 'Doe', 'john.doe@example.com', 'hashed_password', 'Personel', 32),
                                                                        ('Jane', 'Smith', 'jane.smith@example.com', 'hashed_password', 'Şube Müdürü', 32);

-- Insert sample data into `items`
INSERT INTO items (name, amount) VALUES
                                     ('Monitör', 10),
                                     ('Klavye', 15),
                                     ('Fare', 20);

-- Insert sample data into `requests`
INSERT INTO requests (requester_id, item_name, reason, status, sube) VALUES
    (2, 'Monitör', 'Need for work', 'pending_manager', 32);

-- Insert sample data into `personel_items`
INSERT INTO personel_items (personel_id, item_name) VALUES
    (2, 'Klavye');