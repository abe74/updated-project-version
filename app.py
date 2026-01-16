from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mashemeji_derby_secret_key' # Change this in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sokaticket.db'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False) # New field for Admin Check
    tickets = db.relationship('Ticket', backref='owner', lazy=True)

class Match(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    home_team = db.Column(db.String(100), nullable=False)
    away_team = db.Column(db.String(100), nullable=False)
    venue = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    price = db.Column(db.Integer, nullable=False) # Price in KES

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    match_id = db.Column(db.Integer, db.ForeignKey('match.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_for_sale = db.Column(db.Boolean, default=False) # Smart feature: Allow resale
    match = db.relationship('Match')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---

@app.route('/')
def home():
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials. Jaribu tena.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'warning')
            return redirect(url_for('register'))
            
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Login now.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Show all upcoming matches
    matches = Match.query.all()
    # Also show tickets listed for resale by other users
    resale_tickets = Ticket.query.filter(Ticket.is_for_sale == True, Ticket.user_id != current_user.id).all()
    return render_template('dashboard.html', matches=matches, resale_tickets=resale_tickets)

 # [Inside app.py] Paste this after the dashboard route

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    # Security Check: Kick out non-admins
    if not current_user.is_admin:
        flash("Access Denied: Admins Only.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Admin adding a new game
        home = request.form.get('home_team')
        away = request.form.get('away_team')
        venue = request.form.get('venue')
        price = request.form.get('price')
        date_str = request.form.get('date') # Expecting YYYY-MM-DDTHH:MM format
        
        # Convert string date to Python datetime object
        match_date = datetime.strptime(date_str, '%Y-%m-%dT%H:%M')
        
        new_match = Match(home_team=home, away_team=away, venue=venue, price=price, date=match_date)
        db.session.add(new_match)
        db.session.commit()
        flash(f'Match {home} vs {away} created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    # Show existing matches to the admin
    matches = Match.query.order_by(Match.date).all()
    return render_template('admin_dashboard.html', matches=matches)   

@app.route('/buy_ticket/<int:match_id>')
@login_required
def buy_ticket(match_id):
    # In a real app, M-Pesa API integration happens here
    new_ticket = Ticket(match_id=match_id, user_id=current_user.id)
    db.session.add(new_ticket)
    db.session.commit()
    flash('Ticket Purchased Successfully via M-Pesa!', 'success')
    return redirect(url_for('my_tickets'))

@app.route('/buy_resale/<int:ticket_id>')
@login_required
def buy_resale(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    # Transfer ownership
    ticket.user_id = current_user.id
    ticket.is_for_sale = False
    db.session.commit()
    flash('You bought a resale ticket!', 'success')
    return redirect(url_for('my_tickets'))

@app.route('/my_tickets')
@login_required
def my_tickets():
    tickets = Ticket.query.filter_by(user_id=current_user.id).all()
    return render_template('my_tickets.html', tickets=tickets)

@app.route('/sell_ticket/<int:ticket_id>')
@login_required
def sell_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.user_id == current_user.id:
        ticket.is_for_sale = not ticket.is_for_sale # Toggle status
        db.session.commit()
        status = "on sale" if ticket.is_for_sale else "off sale"
        flash(f'Ticket is now {status}.', 'info')
    return redirect(url_for('my_tickets'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Seeding Data (Run once) ---

def seed_data():
    if not User.query.filter_by(username='admin').first():
        # Create a default admin
        admin_pass = generate_password_hash('admin123', method='pbkdf2:sha256')
        admin = User(username='admin', password=admin_pass, is_admin=True)
        db.session.add(admin)
        db.session.commit()
        print("Admin user created (User: admin, Pass: admin123)")