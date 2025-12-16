from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from sqlalchemy.dialects.postgresql import JSONB
import os
import uuid
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
# --- 1. Initialization ---
app = Flask(__name__)

load_dotenv()

DATABASE_URL = os.environ.get('DATABASE_URL') or os.getenv('DATABASE_URL')
if not DATABASE_URL:
    DATABASE_URL = 'sqlite:///stationery.db'

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.getenv('SECRET_KEY', str(uuid.uuid4())))
app.config['CORS_HEADERS'] = 'Content-Type'

db = SQLAlchemy(app)
CORS(app) 

# --- 3. Database Models ---

# User Model (For FR1, FR2)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False) # Store hashed passwords in a real app
    # Role for RBAC (e.g., 'admin', 'buyer')
    role = db.Column(db.String(20), nullable=False, default='buyer')

# Categories Model (For FR11, FR14)
class Category(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    items = db.relationship('Item', backref='category', lazy='dynamic') # Used for cascaded updates (FR13)

    def to_dict(self):
        return {'id': self.id, 'name': self.name}

# Items Model (For FR6, FR8, FR9)
class Item(db.Model):
    # FR6: Unique Item ID
    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    department = db.Column(db.String(100), nullable=False) # FR6: Department Issued To
    issued_date = db.Column(db.Date, nullable=False)      # FR6: Issued Date
    
    # FR11: Foreign Key link to Category
    category_id = db.Column(db.String(50), db.ForeignKey('category.id'), nullable=True)
    
    # FR9: Dynamic input fields (PostgreSQL's JSONB for flexible attribute storage)
    dynamic_attributes = db.Column(JSONB, default={})

    def to_dict(self):
        data = {
            'id': self.id,
            'name': self.name,
            'department': self.department,
            'issuedDate': self.issued_date.isoformat(), 
            'categoryId': self.category_id,
        }
        # Merge dynamic attributes (e.g., 'serialNumber') into the main dict
        if self.dynamic_attributes:
            data.update(self.dynamic_attributes)
        return data

# --- 4. API Endpoints ---

## A. User Authentication Module (FR1, FR2)

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'Invalid username or password'}), 401

    try:
        if check_password_hash(user.password, password):
            return jsonify({'message': 'Login successful', 'user': {'username': user.username, 'role': user.role}}), 200
    except Exception:
        pass

    if user.password == password:
        try:
            user.password = generate_password_hash(password)
            db.session.commit()
        except Exception:
            db.session.rollback()
        return jsonify({'message': 'Login successful', 'user': {'username': user.username, 'role': user.role}}), 200

    return jsonify({'message': 'Invalid username or password'}), 401


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'buyer')

    if not username or not password or role not in ('admin', 'buyer'):
        return jsonify({'message': 'username, password and valid role (admin|buyer) are required'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 409
    # Prevent more than one admin
    if role == 'admin' and User.query.filter_by(role='admin').first():
        return jsonify({'message': 'An admin account already exists'}), 403

    try:
        hashed = generate_password_hash(password)
        user = User(username=username, password=hashed, role=role)
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'User created', 'user': {'username': user.username, 'role': user.role}}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error creating user: {e}'}), 500


@app.route('/api/admin-exists', methods=['GET'])
def admin_exists():
    exists = bool(User.query.filter_by(role='admin').first())
    return jsonify({'exists': exists}), 200

@app.route('/api/categories', methods=['GET'])
def get_categories():
    categories = Category.query.order_by(Category.name.asc()).all()
    return jsonify([cat.to_dict() for cat in categories]), 200

@app.route('/api/categories', methods=['POST'])
def create_category():
    data = request.get_json()
    name = data.get('name')
    if not name:
        return jsonify({'message': 'Category name is required'}), 400
    
    # Simple ID generation based on a UUID for uniqueness
    new_id = f"cat-{uuid.uuid4().hex[:8]}"
    
    new_category = Category(id=new_id, name=name)
    try:
        db.session.add(new_category)
        db.session.commit()
        return jsonify(new_category.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Category name already exists or internal error.'}), 409

@app.route('/api/categories/<category_id>', methods=['DELETE'])
def category_detail(category_id):
    category = Category.query.get_or_404(category_id)
    
    # FR14: Delete Category
    try:
        # FR13: Automatically update category associations when deleted
        # Set all items associated with this category to NULL
        category.items.update({'category_id': None}, synchronize_session=False)
        
        db.session.delete(category)
        db.session.commit()
        return jsonify({'message': 'Category deleted successfully'}), 204
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error deleting category: {e}'}), 500

## C. Item Management Module (FR6, FR8, FR9, FR10, FR12/FR13 handling)

@app.route('/api/items', methods=['GET'])
def get_items():
    items = Item.query.order_by(Item.name.asc()).all()
    return jsonify([item.to_dict() for item in items]), 200

@app.route('/api/items', methods=['POST'])
def create_item():
    data = request.get_json()
    
    # FR7: Validate mandatory fields
    if not all([data.get('name'), data.get('department'), data.get('issuedDate')]):
        return jsonify({'message': 'Mandatory fields (name, department, issuedDate) are required.'}), 400

    try:
        # FR6: Generate a unique ID 
        new_id = f"item-{uuid.uuid4().hex[:8]}"
        
        # FR9: Extract dynamic fields and core attributes
        core_fields = ['name', 'department', 'issuedDate', 'categoryId']
        dynamic_attrs = {k: v for k, v in data.items() if k not in core_fields}

        # Convert date string to Python date object
        issued_date_obj = date.fromisoformat(data['issuedDate'])

        new_item = Item(
            id=new_id,
            name=data['name'],
            department=data['department'],
            issued_date=issued_date_obj,
            category_id=data.get('categoryId'),
            dynamic_attributes=dynamic_attrs
        )
        
        db.session.add(new_item)
        db.session.commit()
        return jsonify(new_item.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error creating item: {e}'}), 500

@app.route('/api/items/<item_id>', methods=['PUT', 'DELETE'])
def item_detail(item_id):
    item = Item.query.get_or_404(item_id)

    if request.method == 'PUT':
        # FR8, FR10: Edit existing item and maintain consistency
        data = request.get_json()
        
        # FR9: Extract dynamic fields and core attributes for update
        core_fields = ['name', 'department', 'issuedDate', 'categoryId']
        
        # Update core fields
        item.name = data.get('name', item.name)
        item.department = data.get('department', item.department)
        
        if data.get('issuedDate'):
            item.issued_date = date.fromisoformat(data['issuedDate'])
            
        # Handles category movement via DND (FR12/FR13) or standard edit
        item.category_id = data.get('categoryId', item.category_id)
        
        # FR9: Update dynamic fields
        dynamic_attrs = {k: v for k, v in data.items() if k not in core_fields}
        item.dynamic_attributes = dynamic_attrs

        try:
            # Commit ensures data consistency (FR10)
            db.session.commit()
            return jsonify(item.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': f'Error updating item: {e}'}), 500

    elif request.method == 'DELETE':
        # FR8, FR10: Delete existing item
        try:
            db.session.delete(item)
            db.session.commit()
            return jsonify({'message': 'Item deleted successfully'}), 204
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': f'Error deleting item: {e}'}), 500

# --- 5. Application Runner ---

if __name__ == '__main__':
    # Creates database tables and a default admin user if not present
    with app.app_context():
        try:
            db.create_all()
            if not User.query.filter_by(username='admin').first():
                db.session.add(User(username='admin', password=generate_password_hash('admin'), role='admin')) 
                db.session.commit()
        except Exception as e:
            print("DB init skipped:", e)
        # Initialize default admin user (username: admin, password: admin, role: admin)
        

    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)