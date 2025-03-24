from pymongo import MongoClient
from os import getenv
from dotenv import load_dotenv
from flask_pymongo import PyMongo

load_dotenv()

# Initialize MongoDB connection
mongo = PyMongo()
db = None

def init_db(app):
    global db
    mongo.init_app(app)
    db = mongo.db
