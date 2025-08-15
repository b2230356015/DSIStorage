from flask import abort, Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from dotenv import load_dotenv
import os
import mysql.connector

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = ('auth')

# Load environment variables from .env file
load_dotenv()

# Database setup
try:
	db = mysql.connector.connect(
		host=os.getenv("DB_HOST"),
		user=os.getenv("DB_USER"),
		password=os.getenv("DB_PASSWORD"),
		database=os.getenv("DB_NAME"),
		autocommit=True
	)
	cursor = db.cursor(dictionary=True)

except mysql.connector.Error as e:
	print(f"Error connecting to database: {e}")
	exit()


@app.route('/db-info')
@login_required
def db_info():
	cursor = db.cursor()
	cursor.execute("SELECT DATABASE()")
	current_db = cursor.fetchone()[0]

	cursor.execute("SELECT @@hostname, @@port, @@version")
	hostname, port, version = cursor.fetchone()

	cursor.close()

	return f"Connected to DB: {current_db}, Host: {hostname}, Port: {port}, MySQL Version: {version}"


# User class
class User(UserMixin):
	def __init__(self, id, name, surname, email, role, sube, password_hash):
		self.id = id  # required by flask-login
		self.name = name
		self.surname = surname
		self.email = email
		self.role = role
		self.sube = sube
		self.password_hash = password_hash


@login_manager.user_loader
def load_user(user_id):
	cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
	user = cursor.fetchone()
	if user:
		print(f"[load_user] user id: {user_id}, password_hash: {user['password_hash']}")
		return User(
			user['id'],
			user['name'],
			user['surname'],
			user['email'],
			user['role'],
			user['sube'],
			user['password_hash']
		)
	return None


@app.route('/request-item', methods=['POST'])
@login_required
def request_item():
	item_name = request.form.get('item_name')
	reason = request.form.get('reason')

	if not all([item_name, reason]):
		flash('All fields are required')
		return redirect(url_for('requests_page'))

	cursor.execute("""
	        INSERT INTO requests (requester_id, item_name, reason, sube)
	        VALUES (%s, %s, %s, %s)
	    """, (current_user.id, item_name, reason, current_user.sube))

	if current_user.role == 'Şube Müdürü' or current_user.sube == 'Bilgi Teknolojileri':
		cursor.execute("""
			UPDATE requests
			SET status = 'pending_it'
			WHERE requester_id = %s AND item_name = %s AND reason = %s
		""", (current_user.id, item_name, reason))

	flash('İstek Başarıyla İletildi', 'success')
	return redirect(url_for('requests_page'))


@app.route('/')
def index():
	if current_user.is_authenticated:
		return redirect(url_for('requests_page'))
	return redirect(url_for('auth'))


@app.errorhandler(403)
def forbidden(e):
	return render_template('403.html'), 403


@app.route('/approve-request/<int:request_id>/<approver_type>', methods=['POST'])
@login_required
def approve_request(request_id, approver_type):
	comment = request.form.get('comment')

	# Admin can approve anything
	if current_user.role == 'admin':
		if approver_type == 'manager':
			cursor.execute("""
                UPDATE requests
                SET status = 'pending_it', manager_comment = %s
                WHERE id = %s
            """, (comment, request_id))
		elif approver_type == 'it':
			cursor.execute("SELECT item_name FROM requests WHERE id = %s", (request_id,))
			result = cursor.fetchone()

			if result is None:
				# handle no such request_id found (optional)
				pass
			else:
				item_name = result["item_name"]

				# 2. Check if items table has enough amount
				cursor.execute("SELECT amount FROM items WHERE name = %s", (item_name,))
				item_result = cursor.fetchone()
				print(item_result)

				if item_result is None:
					# handle no such item found (optional)
					print(item_name)
					pass
				else:
					available_amount = item_result["amount"]

					if available_amount >= 1:
						# 3. Reduce the amount in items table
						new_amount = available_amount - 1
						cursor.execute("""
                                    UPDATE items
                                    SET amount = %s
                                    WHERE name = %s
                                """, (new_amount, item_name))

						# 4. Approve the request as you already do
						cursor.execute("""
                                    UPDATE requests
                                    SET status = 'approved', it_comment = %s
                                    WHERE id = %s
                                """, (comment, request_id))

						# Assign item to personnel
						cursor.execute("""
						                    INSERT INTO personel_items (personel_id, item_name)
						                    SELECT requester_id, item_name
						                    FROM requests
						                    WHERE id = %s
						                """, (request_id,))


					else:
						# Not enough items, maybe raise error or set request status to rejected or pending
						pass

	# Manager approval
	elif approver_type == 'manager' and current_user.role == 'Şube Müdürü':
		cursor.execute("""
            UPDATE requests
            SET status = 'pending_it', manager_comment = %s
            WHERE id = %s AND sube = %s
        """, (comment, request_id, current_user.sube))

	# IT approval
	elif approver_type == 'it' and current_user.role == 'Bilgi Müdür':
		cursor.execute("SELECT item_name FROM requests WHERE id = %s", (request_id,))
		result = cursor.fetchone()

		if result is None:
			# handle no such request_id found (optional)
			pass
		else:
			item_name = result["item_name"]

			# 2. Check if items table has enough amount
			cursor.execute("SELECT amount FROM items WHERE name = %s", (item_name,))
			item_result = cursor.fetchone()

			if item_result is None:
				# handle no such item found (optional)
				pass
			else:
				available_amount = item_result["amount"]

				if available_amount >= 1:
					# 3. Reduce the amount in items table
					new_amount = available_amount - 1
					cursor.execute("""
                        UPDATE items
                        SET amount = %s
                        WHERE name = %s
                    """, (new_amount, item_name))

					# 4. Approve the request as you already do
					cursor.execute("""
                        UPDATE requests
                        SET status = 'approved', it_comment = %s
                        WHERE id = %s
                    """, (comment, request_id))

					# Assign item to personnel
					cursor.execute("""
					                    INSERT INTO personel_items (personel_id, item_name)
					                    SELECT requester_id, item_name
					                    FROM requests
					                    WHERE id = %s
					                """, (request_id,))

				else:
					# Not enough items, maybe raise error or set request status to rejected or pending
					pass

	db.commit()
	return redirect(url_for('requests_page'))


@app.route('/reject-request/<int:request_id>/<approver_type>', methods=['POST'])
@login_required
def reject_request(request_id, approver_type):
	comment = request.form.get('comment')

	# Admin can reject anything
	if current_user.role == 'admin':
		if approver_type == 'manager':
			cursor.execute("""
                UPDATE requests
                SET status = 'rejected', manager_comment = %s
                WHERE id = %s
            """, (comment, request_id))
		elif approver_type == 'it':
			cursor.execute("""
                UPDATE requests
                SET status = 'rejected', it_comment = %s
                WHERE id = %s
            """, (comment, request_id))

	# Manager rejection
	elif approver_type == 'manager' and current_user.role == 'Şube Müdürü':
		cursor.execute("""
            UPDATE requests
            SET status = 'rejected', manager_comment = %s
            WHERE id = %s AND sube = %s
        """, (comment, request_id, current_user.sube))

	# IT rejection
	elif approver_type == 'it' and current_user.role == 'Bilgi Müdür':
		cursor.execute("""
            UPDATE requests
            SET status = 'rejected', it_comment = %s
            WHERE id = %s
        """, (comment, request_id))

	db.commit()
	return redirect(url_for('requests_page'))


@app.route('/inventory')
@login_required
def inventory():
	if current_user.role not in ['admin', 'Bilgi Müdür']:
		abort(403)
	cursor.execute("SELECT * FROM items ORDER BY name")
	items = cursor.fetchall()
	return render_template('inventory.html', items=items)


@app.route('/dashboard')
@login_required
def dashboard():
    cursor.execute("""
        SELECT item_name, assigned_at
        FROM personel_items
        WHERE personel_id = %s
        ORDER BY item_name ASC
    """, (current_user.id,))
    assigned_items = cursor.fetchall()

    cursor.execute("""
        SELECT COUNT(*) AS total_requests FROM requests WHERE requester_id = %s
    """, (current_user.id,))
    total_requests = cursor.fetchone()['total_requests']

    return render_template('dashboard.html',
                           title='Dashboard',
                           assigned_items=assigned_items,
                           total_requests=total_requests)


@app.route("/requests")
@login_required
def requests_page():
	person_id = request.args.get('person_id')  # Get person_id from query parameters
	sube_id = request.args.get('sube_id')  # Get sube_id from query parameters
	sort_by = request.args.get('sort_by', 'status')  # Default sorting by status
	sort_order = request.args.get('sort_order', 'asc')  # Default sorting order

	# Validate sort_by and sort_order to prevent SQL injection
	valid_columns = ['id', 'name', 'surname', 'item_name', 'sube', 'status']
	if sort_by not in valid_columns:
		sort_by = 'status'
	if sort_order not in ['asc', 'desc']:
		sort_order = 'asc'

	# Handle sorting by name and surname together
	if sort_by == 'name':
		order_clause = f"name {sort_order}, surname {sort_order}"
	else:
		order_clause = f"{sort_by} {sort_order}"

	requests = []  # Initialize requests as an empty list
	personnel = []  # Initialize personnel as an empty list
	sube_list = []  # Initialize sube_list as an empty list

	if current_user.role == 'Bilgi Müdür':
		# Fetch all Şube list
		cursor.execute("SELECT DISTINCT sube AS id, CONCAT('Şube ', sube) AS name FROM users WHERE sube IS NOT NULL")
		sube_list = cursor.fetchall()

		if sube_id:
			# Fetch personnel in the selected Şube
			cursor.execute("""
                SELECT id, name, surname
                FROM users
                WHERE sube = %s AND role = 'Personel'
                ORDER BY name, surname
            """, (sube_id,))
			personnel = cursor.fetchall()

			if person_id:
				# Show requests for a specific person in the selected Şube
				cursor.execute(f"""
                    SELECT r.*, u.name, u.surname
                    FROM requests r
                    JOIN users u ON r.requester_id = u.id
                    WHERE r.sube = %s AND r.requester_id = %s
                    ORDER BY {order_clause}
                """, (sube_id, person_id))
			else:
				# Show all requests for the selected Şube
				cursor.execute(f"""
                    SELECT r.*, u.name, u.surname
                    FROM requests r
                    JOIN users u ON r.requester_id = u.id
                    WHERE r.sube = %s
                    ORDER BY {order_clause}
                """, (sube_id,))
		else:
			# Show all requests across all Şubeler
			cursor.execute(f"""
                SELECT r.*, u.name, u.surname
                FROM requests r
                JOIN users u ON r.requester_id = u.id
                ORDER BY {order_clause}
            """)
		requests = cursor.fetchall()

	elif current_user.role == 'Şube Müdürü':
		# Fetch personnel in the same branch (Şube)
		cursor.execute("""
            SELECT id, name, surname
            FROM users
            WHERE sube = %s AND role = 'Personel'
            ORDER BY name, surname
        """, (current_user.sube,))
		personnel = cursor.fetchall()

		if person_id:
			# Show requests for a specific person in the Şube
			cursor.execute(f"""
                SELECT r.*, u.name, u.surname
                FROM requests r
                JOIN users u ON r.requester_id = u.id
                WHERE r.sube = %s AND r.requester_id = %s
                ORDER BY {order_clause}
            """, (current_user.sube, person_id))
		else:
			# Show all requests for the Şube
			cursor.execute(f"""
                SELECT r.*, u.name, u.surname
                FROM requests r
                JOIN users u ON r.requester_id = u.id
                WHERE r.sube = %s
                ORDER BY {order_clause}
            """, (current_user.sube,))
		requests = cursor.fetchall()

	elif current_user.role == 'Personel':
		# Fetch requests made by the logged-in personnel
		cursor.execute(f"""
            SELECT r.*, u.name, u.surname
            FROM requests r
            JOIN users u ON r.requester_id = u.id
            WHERE r.requester_id = %s
            ORDER BY {order_clause}
        """, (current_user.id,))
		requests = cursor.fetchall()

	return render_template(
		'requests.html',
		title='Requests',
		requests=requests,
		personnel=personnel,  # Pass personnel to the template
		sube_list=sube_list,  # Pass Şube list to the template
		sort_by=sort_by,
		sort_order=sort_order,
		selected_person_id=person_id,  # Pass the selected person ID to the template
		selected_sube_id=sube_id  # Pass the selected Şube ID to the template
	)


@app.route("/rehber")
@login_required
def rehber():
	sube_id = request.args.get('sube_id')  # Get selected Şube ID
	person_id = request.args.get('person_id')  # Get selected Personel ID
	sort_by = request.args.get('sort_by', 'name')  # Default sorting by name
	sort_order = request.args.get('sort_order', 'asc')  # Default sorting order

	# Validate sort_by and sort_order to prevent SQL injection
	valid_columns = ['id', 'name', 'surname', 'email', 'role', 'sube']
	if sort_by not in valid_columns:
		sort_by = 'name'
	if sort_order not in ['asc', 'desc']:
		sort_order = 'asc'

	order_clause = f"{sort_by} {sort_order}"

	# Fetch Şube list sorted by name
	cursor.execute(
		"SELECT DISTINCT sube AS id, CONCAT('Şube ', sube) AS name FROM users WHERE sube IS NOT NULL ORDER BY name")
	sube_list = cursor.fetchall()

	# Fetch users based on filters
	query = """
        SELECT id, name, surname, email, role, sube
        FROM users
        WHERE role IN ('Personel', 'Şube Müdürü', 'Bilgi Müdür')
    """
	params = []

	if sube_id:
		query += " AND sube = %s"
		params.append(sube_id)

	if person_id:
		query += " AND id = %s"
		params.append(person_id)

	query += f" ORDER BY {order_clause}"
	cursor.execute(query, params)
	users = cursor.fetchall()

	return render_template(
		"rehber.html",
		title="Rehber",
		users=users,
		sube_list=sube_list,
		selected_sube_id=sube_id,
		selected_person_id=person_id,
		sort_by=sort_by,
		sort_order=sort_order
	)


@app.route('/transfer-items', methods=['GET', 'POST'])
@login_required
def transfer_items():
	if current_user.role != 'Bilgi Müdür' and current_user.role != 'admin':
		abort(403)

	if request.method == 'POST':
		personel_id = request.form.get('personel_id')
		item_name = request.form.get('item_name')

		if not personel_id or not item_name:
			flash('Please select a personel and an item.', 'danger')
			return redirect(url_for('transfer_items'))

		# Remove the item from the personel
		cursor.execute("""
            DELETE FROM personel_items
            WHERE personel_id = %s AND item_name = %s
            LIMIT 1
        """, (personel_id, item_name))

		# Add the item back to the depo
		cursor.execute("""
            UPDATE items
            SET amount = amount + 1
            WHERE name = %s
        """, (item_name,))

		db.commit()
		flash('Eşya Başarıyla Depoya Teslim Edildi', 'success')

	# Fetch all personnel and their items
	cursor.execute("""
        SELECT u.id AS personel_id, u.name, u.surname, u.sube AS sube_id, pi.item_name
        FROM users u
        LEFT JOIN personel_items pi ON u.id = pi.personel_id
        WHERE u.role IN ('Personel', 'Şube Müdürü')
        ORDER BY u.name, u.surname
    """)
	personnel_items = cursor.fetchall()

	# Create unique person list
	persons = {}
	for row in personnel_items:
		persons[row['personel_id']] = {
			'personel_id': row['personel_id'],
			'name': row['name'],
			'surname': row['surname'],
			'sube_id': row['sube_id']
		}
	persons_list = list(persons.values())

	# Fetch Şube list
	cursor.execute("SELECT DISTINCT sube AS id, CONCAT('Şube ', sube) AS name FROM users WHERE sube IS NOT NULL order by sube ASC")
	sube_list = cursor.fetchall()

	return render_template(
		"transfer_items.html",
		persons_list=persons_list,  # For first dropdown
		personnel_items=personnel_items,  # For later filtering
		sube_list=sube_list  # For Şube dropdown
	)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
	# Assume your User model has these fields:
	# name, surname, email, password_hash, role, sube

	from main import db

	if request.method == "POST":
		form_type = request.form.get("form_type")

		if form_type == "update_email":
			new_email = request.form.get("email", "").strip()
			if not new_email:
				flash("Email cannot be empty.", "danger")
			elif new_email == current_user.email:
				flash("This is already your current email.", "warning")
			else:
				# Check if email already exists for a different user
				cursor.execute("SELECT id FROM users WHERE email = %s AND id != %s", (new_email, current_user.id))
				existing = cursor.fetchone()
				if existing:
					flash("This email is already in use by another account.", "danger")
				else:
					cursor.execute("UPDATE users SET email = %s WHERE id = %s", (new_email, current_user.id))
					db.commit()
					current_user.email = new_email
					flash("Email Başarıyla Güncellendi", "success")
					return redirect(url_for("settings"))

		elif form_type == "change_password":
			old_password = request.form.get("old_password", "")
			new_password = request.form.get("new_password", "")
			confirm_password = request.form.get("confirm_password", "")

			if not old_password or not new_password or not confirm_password:
				flash("Please fill in all password fields.", "danger")
			elif not bcrypt.check_password_hash(current_user.password_hash, old_password):
				flash("Old password is incorrect.", "danger")
			elif new_password != confirm_password:
				flash("New password and confirmation do not match.", "danger")
			else:
				hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
				cursor.execute("""UPDATE users SET password_hash = %s WHERE id = %s""",
				               (hashed_password, current_user.id))
				print("Rows updated:", cursor.rowcount)
				db.commit()
				cursor.execute("SELECT password_hash FROM users WHERE id = %s", (current_user.id,))
				result = cursor.fetchone()
				print("New password hash:", result['password_hash'])
				db.close()
				db = mysql.connector.connect(
					host="127.0.0.1",
					user="root",
					password="123456789",
					database="my_database"
				)
				cursor.execute("SELECT password_hash FROM users WHERE id = %s", (current_user.id,))
				result = cursor.fetchone()
				print("New password hash:", result['password_hash'])

				# Reload the user from the database
				cursor.execute("SELECT * FROM users WHERE id = %s", (current_user.id,))
				user = cursor.fetchone()
				if user:
					updated_user = User(
						user['id'],
						user['name'],
						user['surname'],
						user['email'],
						user['role'],
						user['sube'],
						user['password_hash']
					)
					login_user(updated_user)  # Update the session with the new user object

				flash("Şifre Başarıyla Güncellendi", "success")
				return redirect(url_for("settings"))

	return render_template("settings.html", title="Profile", user=current_user)


@app.route('/auth', methods=['GET', 'POST'])
def auth():
	action = request.args.get('action', 'login')
	cursor.execute("SELECT DISTINCT sube FROM users WHERE sube IS NOT NULL order by sube ASC")
	subeler = [row["sube"] for row in cursor.fetchall()]

	if request.method == 'POST':
		email = request.form.get('email')
		password = request.form.get('password')

		if not email or not password:
			flash('Email and password are required.')
			return redirect(url_for('auth', action=action))

		if action == 'login':
			cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
			user = cursor.fetchone()
			if user and bcrypt.check_password_hash(user['password_hash'], password):
				user_obj = User(user['id'], user['name'], user['surname'], user['email'], user['role'], user['sube'],
				                user['password_hash'])
				login_user(user_obj)
				if user['role'] == 'Bilgi Müdür':
					return redirect(url_for('requests_page'))
				return redirect(url_for('dashboard'))
			flash('Invalid login credentials')

		elif action == 'register':
			name = request.form.get('name')
			surname = request.form.get('surname')
			role = request.form.get('role')
			sube = request.form.get('sube')
			confirm_password = request.form.get('confirm_password')

			if not all([name, surname, role, password, confirm_password]):
				flash('All fields are required')
				return redirect(url_for('auth', action=action))

			if password != confirm_password:
				flash('Passwords do not match')
				return redirect(url_for('auth', action=action))

			cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
			if cursor.fetchone():
				flash('Email already registered')
				return redirect(url_for('auth', action=action))

			sube = sube if role in ['Personel', 'Şube Müdürü'] else None
			hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

			cursor.execute("""
                INSERT INTO users (email, password_hash, name, surname, role, sube) 
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (email, hashed_password, name, surname, role, sube))
			db.commit()

			cursor.execute("SELECT * FROM users WHERE id = %s", (cursor.lastrowid,))
			user = cursor.fetchone()
			if user:
				user_obj = User(
					user['id'], user['name'], user['surname'], user['email'],
					user['role'], user['sube'], user['password_hash']
				)
				login_user(user_obj)
			if user['role'] == 'Bilgi Müdür':
				return redirect(url_for('requests_page'))
			return redirect(url_for("dashboard"))

	return render_template('auth.html', action=action, subeler=subeler)


@app.route('/logout')
@login_required
def logout():
	logout_user()
	flash('You have been logged out.')
	return redirect(url_for('auth', action='login'))


if __name__ == '__main__':
	app.run(debug=True)
