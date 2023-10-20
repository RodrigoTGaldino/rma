from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token


app = Flask(__name__)
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "mysql+mysqlconnector://root:arthur@localhost/ram"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "MariTutas"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = False

db = SQLAlchemy(app)
jwt = JWTManager(app)


class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(25), nullable=False)
    cpf = db.Column(db.String(11), nullable=False)
    telefone = db.Column(db.String(20), nullable=False)
    empresa = db.Column(db.String(50), nullable=False)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    produto = db.Column(db.String(20), nullable=False)
    quantidade = db.Column(db.Integer, nullable=False)
    valor = db.Column(db.Float, nullable=False)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(100), nullable=False)  # Password should be a string


# Rota para registro de usuário
@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(
        username=username
    ).first()  # Check if the user already exists
    if user:
        return jsonify({"error": "Nome de usuário já está em uso."}), 400

    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Registro bem-sucedido!"}), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()
    if user and user.password == password:
        access_token = create_access_token(identity=user.id)
        return jsonify({"access_token": access_token}), 200
    else:
        return jsonify({"error": "Credenciais inválidas."}), 401


# Rota protegida para adicionar um novo cliente (requer autenticação)
@app.route("/api/add_cliente", methods=["POST"])
@jwt_required()
def adicionar_cliente():
    data = request.json
    nome = data.get("nome")
    cpf = data.get("cpf")
    telefone = data.get("telefone")
    empresa = data.get("empresa")

    new_customer = Customer(nome=nome, cpf=cpf, telefone=telefone, empresa=empresa)
    db.session.add(new_customer)
    db.session.commit()

    return jsonify({"message": "Cliente adicionado com sucesso!"}), 201


@app.route("/api/clientes", methods=["GET"])
@jwt_required()
def lista_clientes():
    customers = Customer.query.all()
    customer_list = [
        {
            "nome": customer.nome,
            "cpf": customer.cpf,
            "telefone": customer.telefone,
            "empresa": customer.empresa,
        }
        for customer in customers
    ]
    return jsonify({"customers": customer_list})


# Rota protegida para adicionar um novo produto (requer autenticação)
@app.route("/api/add_product", methods=["POST"])
@jwt_required()
def add_product():
    data = request.json
    produto = data.get("produto")
    quantidade = data.get("quantidade")
    valor = data.get("valor")

    new_product = Product(produto=produto, quantidade=quantidade, valor=valor)
    db.session.add(new_product)
    db.session.commit()
    return jsonify({"message": "Produto adicionado com sucesso!"}), 201


@app.route("/api/products", methods=["GET"])
@jwt_required()
def list_products():
    products = Product.query.all()
    products_list = [
        {
            "produto": product.produto,
            "quantidade": product.quantidade,
            "valor": product.valor,
        }
        for product in products
    ]
    return jsonify({"products": products_list})


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
