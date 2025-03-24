from flask_login import UserMixin
from bson import ObjectId

class User(UserMixin):
    """
    User class for Flask-Login integration with MongoDB users collection
    """
    
    def __init__(self, user_data):
        """
        Initialize a User instance from MongoDB document data
        
        Args:
            user_data (dict): User data from MongoDB users collection
        """
        self.id = str(user_data.get('_id'))
        self.email = user_data.get('email')
        self.password = user_data.get('password')  # This is the hashed password
        self.first_name = user_data.get('first_name')
        self.last_name = user_data.get('last_name')
        self.profile_pic = user_data.get('profile_pic')
        self.created_at = user_data.get('created_at')
        self.role = user_data.get('role', 'user')
        # Add any additional user properties as needed

    def get_id(self):
        """
        Override the get_id method from UserMixin
        
        Returns:
            str: The user ID as a string
        """
        return self.id
    
    def is_active(self):
        """
        Override is_active method from UserMixin
        All users are active by default
        
        Returns:
            bool: True if the user is active
        """
        return True
    
    def is_anonymous(self):
        """
        Override is_anonymous method from UserMixin
        
        Returns:
            bool: False as this represents an authenticated user
        """
        return False
    
    def is_authenticated(self):
        """
        Override is_authenticated method from UserMixin
        
        Returns:
            bool: True as this represents an authenticated user
        """
        return True
    
    def has_role(self, role):
        """
        Check if the user has a specific role
        
        Args:
            role (str): The role to check
            
        Returns:
            bool: True if the user has the specified role
        """
        return self.role == role or self.role == 'admin'
    
    def to_json(self):
        """
        Convert user data to JSON serializable dictionary
        (Excludes password for security)
        
        Returns:
            dict: User data as dictionary
        """
        return {
            'id': self.id,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'profile_pic': self.profile_pic,
            'created_at': self.created_at,
            'role': self.role
        }
    
    @staticmethod
    def find_by_email(users_collection, email):
        """
        Find a user by email in the database
        
        Args:
            users_collection: MongoDB collection for users
            email (str): Email to search for
            
        Returns:
            User or None: User instance if found, None otherwise
        """
        user_data = users_collection.find_one({'email': email})
        if user_data:
            return User(user_data)
        return None
    
    @staticmethod
    def find_by_id(users_collection, user_id):
        """
        Find a user by ID in the database
        
        Args:
            users_collection: MongoDB collection for users
            user_id (str): User ID to search for
            
        Returns:
            User or None: User instance if found, None otherwise
        """
        try:
            user_data = users_collection.find_one({'_id': ObjectId(user_id)})
            if user_data:
                return User(user_data)
        except:
            pass
        return None
