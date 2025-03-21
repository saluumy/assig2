from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import pymysql

# Database Configuration
DB_NAME = "anu_store"
DB_USER = "root"
DB_PASSWORD = ""  
DB_HOST = "localhost"
DB_PORT = 3306
SECRET_KEY = "anu"  

# Create the database 
connection = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD, port=DB_PORT)
cursor = connection.cursor()
cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
cursor.close()
connection.close()

# Initialize Flask app & database
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = SECRET_KEY

db = SQLAlchemy(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Hashed password

# Product Model
class Product(db.Model):
    pid = db.Column(db.Integer, primary_key=True)
    pname = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Create tables
with app.app_context():
    db.create_all()

# JWT Token Validation Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"message": "Token is missing!"}), 401
        try:
            token = token.split(" ")[1]  # Remove "Bearer"
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data["user_id"]).first()
            if not current_user:
                return jsonify({"message": "User not found!"}), 401
        except:
            return jsonify({"message": "Token is invalid!"}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# User Registration (SignUp)
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    hashed_password = generate_password_hash(data["password"], method="pbkdf2:sha256")
    new_user = User(name=data["name"], username=data["username"], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully!"})

# User Login
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    user = User.query.filter_by(username=data["username"]).first()
    if user and check_password_hash(user.password, data["password"]):
        token = jwt.encode({"user_id": user.id, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=10)},
                           app.config["SECRET_KEY"], algorithm="HS256")
        return jsonify({"token": token})
    return jsonify({"message": "Invalid credentials!"}), 401

# Get All Users (Protected - Requires JWT)
@app.route("/users", methods=["GET"])
@token_required
def get_users(current_user):
    users = User.query.all()
    return jsonify([{"id": user.id, "name": user.name, "username": user.username} for user in users])

# Add New Product (Protected - Requires JWT)
@app.route("/products", methods=["POST"])
@token_required
def add_product(current_user):
    data = request.json
    new_product = Product(
        pname=data["pname"],
        description=data.get("description", ""),
        price=data["price"],
        stock=data["stock"]
    )
    db.session.add(new_product)
    db.session.commit()
    return jsonify({"message": "Product added successfully!"})

# Get All Products (Protected - Requires JWT)
@app.route("/products", methods=["GET"])
@token_required
def get_products(current_user):
    products = Product.query.all()
    return jsonify([
        {"pid": p.pid, "pname": p.pname, "description": p.description, "price": p.price, "stock": p.stock, "created_at": p.created_at}
        for p in products
    ])

# Get a Product by ID (Protected - Requires JWT)
@app.route("/products/<int:pid>", methods=["GET"])
@token_required
def get_product(current_user, pid):
    product = Product.query.get(pid)
    if not product:
        return jsonify({"message": "Product not found"}), 404
    return jsonify({
        "pid": product.pid,
        "pname": product.pname,
        "description": product.description,
        "price": product.price,
        "stock": product.stock,
        "created_at": product.created_at
    })

# Update Product by ID (Protected - Requires JWT)
@app.route("/products/<int:pid>", methods=["PUT"])
@token_required
def update_product(current_user, pid):
    product = Product.query.get(pid)
    if not product:
        return jsonify({"message": "Product not found"}), 404

    data = request.json
    product.pname = data.get("pname", product.pname)
    product.description = data.get("description", product.description)
    product.price = data.get("price", product.price)
    product.stock = data.get("stock", product.stock)

    db.session.commit()
    return jsonify({"message": "Product updated successfully!"})

# Delete Product by ID (Protected - Requires JWT)
@app.route("/products/<int:pid>", methods=["DELETE"])
@token_required
def delete_product(current_user, pid):
    product = Product.query.get(pid)
    if not product:
        return jsonify({"message": "Product not found"}), 404

    db.session.delete(product)
    db.session.commit()
    return jsonify({"message": "Product deleted successfully!"})

if __name__ == "__main__":
    app.run(debug=True)
