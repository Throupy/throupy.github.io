---
title: Creating Flask Applications using an Application Factory Approach
description: An overview of the Flask "application factory" approach and its benefits.
date: 2024-06-08 00:00:00 +0000
categories: [CTF]
tags: [ctf, web]
image: /assets/img/banners/factory.png
---

# Creating Flask Applications using an Application Factory Approach
Creating flask applications using the `create_app` "factory method" is a powerful approach for building scalable web applications without sacrificing maintainability. This approach allows for more efficient application structuring, which makes it easier to manage, test, and extend a web application.

## File Structure
Here's a typical file structure for a Flask application using the `create_app` method and registering multiple services

```
FLASKAPP/
│
├── webapp/
│   ├── __init__.py
│   ├── routes.py
│   ├── models.py
│   ├── forms.py
│   ├── config.py
│   ├── extensions.py
│   ├── main/
│      ├── __init__.py
│      ├── routes.py
│      └── templates/
│           └── index.html
├── migrations/
├── tests/
│
├── .gitignore
└── run.py
```

## File Contents and Explanations

### `run.py`
This file acts as the entry point for the application. When using the flask environment, this is the default file which will be executed when the `flask run` command is used.

This script imports the `create_app` factory function from the application package, and initialises the application. By using this approach, it is ensured that the application configuration and registration of extensions and blueprints are handled consistently.

```python
# run.py
from webapp import create_app

app = create_app()

if __name__ == "__main__":
    app.run() # you can pass some args here e.g. 
              # host="0.0.0.0", debug=True, and so on
```

In this setup, `run.py` is minimal, which it should be. This keeps the application startup logic centralized within the `create_app` function, which will be explained in the following section.

### `extensions.py`
This file contains "uninitialised extensions". That is, extension instances that are not aware of the flask application, but will be imported and initialised later (in `create_app`).

```python
# extensions.py
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from celery import Celery
from flask_login import LoginManager
from flask_mail import Mail

db = SQLAlchemy()
migrate = Migrate()
celery = Celery(__name__, broker='redis://localhost:6379/0')
login_manager = LoginManager()
mail = Mail()
```

This module helps to decouple the initialisation of extensions from the application instance, promoting a cleaner codebase. By placing all extension initialisations in a separate module, the application structure is kept organised and modular.

### `__init__.py` and the `create_app` function
The `__init__.py` file within the `webapp` directory makes `webapp` a python package. More information about python package (and module) structure can be found [here](https://docs.python.org/3/reference/import.html#regular-packages).

In this case, the `__init__.py` file contains the `create_app` factory function for creating the flask application instance. This function initialises the application, loads configuration, and registered additional extensions and blueprints. By keeping this function clean, simple, and focused, an application is much easier to manage and extend.

A little about registering extensions - when extensions are initialised within the `create_app` function, the `Flask` instance is passed as an argument. This ties something called the "application context" to the extension, ensuring they operate within the correct application environment. For example:
- `db.init_app(app)` ties the SQLAlchemy database instance to the application, allowing it to know which configuration and context to use

By initialising extensions within the application context, it is ensured that they are aware of and can interact with the application's configuration and state.

```python
# webapp/__init__.py
from flask import Flask
from webapp.extensions import db, migrate, celery, login_manager, mail
from webapp.config import Config
from webapp.main.routes import main_bp

def create_app(config_class=Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions defined in webapp/extensions.py
    db.init_app(app)
    migrate.init_app(app, db)
    celery.conf.update(app.config)
    login_manager.init_app(app)
    mail.init_app(app)

    # Register blueprints
    app.register_blueprints(main_bp)

    return app
```

### `config.py` and the Configuration class
This module contains configuration settings for the application in the form of a class. This configuration defines settings for various extensions. Having a centralised configuration file allows for easy changing of settings. This is a good place to import secret variables from environment variables, if necessary. An example configuration class for the registered services can be found below.

```python
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL') or 'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND') or 'redis://localhost:6379/0'
    MAIL_SERVER = 'smtp.example.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
```

### `main` Directory and Blueprints
Flask promotes the use of Blueprints when creating larger applications. The official flask documentation covers blueprints pretty well, and can be found [here](https://flask.palletsprojects.com/en/3.0.x/blueprints/)

Within the `main` directory, the `routes.py` file can be found, within which the blueprint will be defined, along with any relevant routes. Typically, blueprints can represent a different part of an application functionality, for example:
- `users` Blueprint - contains logic and routes pertaining to user functionality (e.g. login, logout, update account)
- `posts` Blueprint - in a blog application (or similar), this would contain routes for viewing, create, delete, posts, and so on.

Within the `main` directory, it is also advised to store any blueprint-specific forms, utility functions etc. Sticking with the example above, the `users` blueprint may contain a `forms.py` with Login / Registration forms, and some utility functions (`utils.py`) which are used to check hashed passwords to validate a login, for example.

```python
# webapp/main/routes.py
from flask import Blueprint, render_template

main_bp = Blueprint("main", __name__)

@main_bp.route("/")
@main_bp.route("/index")
def index():
    return render_template("index.html")
```

There are additional argument that can be passed to the Blueprint object, such as a dedicated template / static folder, or a URL prefix. Read the documentation linked above for more information.

While the usage will vary depending on the application, an example of `users/forms.py` can be found below.
```python
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')
```

### `models.py` 
`models.py` is usually independent of blueprints, that is, it is stored in the root directory of the application (`webapp/`, in this context). However, there can also be a separate `models.py` for each blueprint, should that be necessary.

Again, the usage will vary depending on the application, but below is an example of `models.py`. 

```python
from webapp.extensions import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
```

Notice now webapp.extensions contains db, which is the now-initialised SQLAlchemy object, which can be used easily and efficiently.

## Ease of Access
One of the significant advantages of using the `create_app` factory method and modular design in Flask application is the "ease of access" to various components across the application. Models, forms, and other components can be imported with ease across the application, in a way that is clear and intuitive:

Easily import a model from `models.py`, or a Registration form:
```python
from webapp.models import User
from webapp.users.forms import RegistrationForm
```

## Benefits and Conclusion
Benefits of the `create_app` Approach include:
1. Modularity: The factory method promotes a modular architecture by allowing for registration of blueprints, which are self-contained components of the application.
2. Configurable: It enables configuration of the application dynamically, supporting multiple environments (development, testing, production).
3. Testability: The factory method makes it easier to create and manage application instances for testing purposes.
4. Scalability: The modular structure makes it simpler to add new features without impacting the entire application.

With this setup, a modular and scalable Flask application has been created using the create_app factory method. The inclusion of multiple services such as SQLAlchemy, Celery, Login Manager, and Flask-Mail demonstrates the power and flexibility of this approach. Each component is neatly separated, making the application easier to manage and extend as it grows. Initializing the extensions within the create_app function ties them to the application context, ensuring they operate within the correct environment and interact with the application's configuration and state. This method also promotes best practices in organizing the Flask application, ensuring it remains maintainable and scalable as more features are added. Moreover, the ease of access to various modules greatly enhances code readability and maintainability, allowing for efficient management and extension of an application's functionality.

As always, the code for this blog can be found [here](https://github.com/Throupy/blog-projects/tree/main/flask-create-app)