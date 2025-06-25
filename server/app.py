#!/usr/bin/env python3

from flask import request, session, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        
        try:
            # Move user creation inside the try block to catch validation errors
            new_user = User(
                username=data.get('username'),
                image_url=data.get('image_url'),
                bio=data.get('bio')
            )

            # Move password hashing inside the try block to catch errors from missing password
            new_user.password_hash = data.get('password')

            db.session.add(new_user)
            db.session.commit()
            
            session['user_id'] = new_user.id
            
            return make_response(new_user.to_dict(rules=('-recipes',)), 201)
        
        except IntegrityError:
            db.session.rollback()
            return make_response({'errors': ['Username has already been taken']}, 422)
        
        except (ValueError, AttributeError) as e:
            # Catch both model validation errors and errors from missing attributes
            db.session.rollback()
            return make_response({'errors': [str(e) for e in e.args]}, 422)


class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.filter(User.id == user_id).first()
            if user:
                return make_response(user.to_dict(rules=('-recipes',)), 200)
        
        return {'error': 'Unauthorized'}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter(User.username == username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return make_response(user.to_dict(rules=('-recipes',)), 200)
        
        return make_response({'error': 'Unauthorized'}, 401)

class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session['user_id'] = None
            return make_response({}, 204)
        
        return make_response({'error': 'Unauthorized'}, 401)

class RecipeIndex(Resource):
    def get(self):
        if not session.get('user_id'):
            return make_response({'error': 'Unauthorized'}, 401)
        
        recipes = Recipe.query.all()
        return make_response([recipe.to_dict() for recipe in recipes], 200)

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return make_response({'error': 'Unauthorized'}, 401)
        
        data = request.get_json()

        try:
            new_recipe = Recipe(
                title=data.get('title'),
                instructions=data.get('instructions'),
                minutes_to_complete=data.get('minutes_to_complete'),
                user_id=user_id
            )
            db.session.add(new_recipe)
            db.session.commit()
            return make_response(new_recipe.to_dict(), 201)
        except (IntegrityError, ValueError) as e:
            db.session.rollback()
            return make_response({'errors': [str(e) for e in e.args]}, 422)

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)