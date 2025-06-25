#!/usr/bin/env python3

from flask import request, session, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        # Get data from the request
        data = request.get_json()

        # Create a new User instance
        new_user = User(
            username=data.get('username'),
            image_url=data.get('image_url'),
            bio=data.get('bio')
        )

        # Set the password, which will be hashed by the setter in the model
        new_user.password_hash = data.get('password')

        try:
            # Add and commit the new user to the database
            db.session.add(new_user)
            db.session.commit()
            
            # Save the user's ID in the session
            session['user_id'] = new_user.id
            
            # Return the user's data with a 201 status code
            return make_response(new_user.to_dict(), 201)

        except IntegrityError:
            # Handle cases where the username is not unique
            db.session.rollback()
            return {'errors': ['Username has already been taken']}, 422
        except ValueError as e:
            # Handle validation errors from the model
            db.session.rollback()
            return {'errors': [str(e) for e in e.args]}, 422


class CheckSession(Resource):
    def get(self):
        # Check if user_id is in the session
        user_id = session.get('user_id')
        if user_id:
            # Find the user by their ID
            user = User.query.filter(User.id == user_id).first()
            if user:
                # If user is found, return their data
                return make_response(user.to_dict(), 200)
        
        # If no user_id in session or user not found, return unauthorized
        return {'error': 'Unauthorized'}, 401


class Login(Resource):
    pass

class Logout(Resource):
    pass

class RecipeIndex(Resource):
    pass

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)