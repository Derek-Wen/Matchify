from flask import Flask, request, redirect, render_template, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import BooleanField, SubmitField
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from dotenv import load_dotenv
from collections import Counter
import requests
import base64
import os
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
import logging

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_default_secret_key')

# Update the SQLAlchemy Database URI
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
# Fix for Heroku's DATABASE_URL starting with 'postgres://'
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://')

# Security Configurations
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)
migrate = Migrate(app, db)

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Spotify API credentials
client_id = os.getenv('SPOTIFY_CLIENT_ID', '').strip()
client_secret = os.getenv('SPOTIFY_CLIENT_SECRET', '').strip()
redirect_uri = os.getenv('REDIRECT_URI', '').strip()

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    spotify_id = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(150), nullable=False)
    profile_image = db.Column(db.String(200))
    access_token = db.Column(db.String(500))
    refresh_token = db.Column(db.String(500))
    share_data = db.Column(db.Boolean, default=True)

# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Privacy Form
class PrivacyForm(FlaskForm):
    share_data = BooleanField('Allow other users to compare with me')
    submit = SubmitField('Update')

# Helper Functions
def refresh_access_token(user):
    token_url = 'https://accounts.spotify.com/api/token'
    payload = {
        'grant_type': 'refresh_token',
        'refresh_token': user.refresh_token,
    }
    client_creds = f"{client_id}:{client_secret}"
    client_creds_b64 = base64.b64encode(client_creds.encode())
    headers = {
        'Authorization': f'Basic {client_creds_b64.decode()}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    response = requests.post(token_url, data=payload, headers=headers)
    response_data = response.json()
    if 'access_token' in response_data:
        user.access_token = response_data['access_token']
        db.session.commit()
        logger.info(f"Access token refreshed for user {user.username}")
        return True
    else:
        logger.error(f"Failed to refresh access token for user {user.username}: {response_data}")
        return False

def get_user_top_artists(user, time_range='medium_term'):
    headers = {
        'Authorization': f'Bearer {user.access_token}'
    }
    params = {'limit': 20, 'time_range': time_range}
    response = requests.get('https://api.spotify.com/v1/me/top/artists', headers=headers, params=params)
    if response.status_code == 200:
        return response.json()['items']
    elif response.status_code == 401:
        # Token expired, refresh it
        if refresh_access_token(user):
            headers['Authorization'] = f'Bearer {user.access_token}'
            response = requests.get('https://api.spotify.com/v1/me/top/artists', headers=headers, params=params)
            if response.status_code == 200:
                return response.json()['items']
        flash(f"Failed to fetch top artists for user {user.username}.")
        return []
    else:
        logger.error(f"Error fetching top artists for user {user.username}: {response.status_code} {response.text}")
        return []

def get_user_top_tracks(user, time_range='medium_term'):
    headers = {
        'Authorization': f'Bearer {user.access_token}'
    }
    params = {'limit': 20, 'time_range': time_range}
    response = requests.get('https://api.spotify.com/v1/me/top/tracks', headers=headers, params=params)
    if response.status_code == 200:
        return response.json()['items']
    elif response.status_code == 401:
        # Token expired, refresh it
        if refresh_access_token(user):
            headers['Authorization'] = f'Bearer {user.access_token}'
            response = requests.get('https://api.spotify.com/v1/me/top/tracks', headers=headers, params=params)
            if response.status_code == 200:
                return response.json()['items']
        flash(f"Failed to fetch top tracks for user {user.username}.")
        return []
    else:
        logger.error(f"Error fetching top tracks for user {user.username}: {response.status_code} {response.text}")
        return []

def get_tracks_audio_features(user, user_tracks):
    track_ids = [track['id'] for track in user_tracks]
    audio_features = []
    headers = {
        'Authorization': f'Bearer {user.access_token}'
    }
    for i in range(0, len(track_ids), 100):
        batch_ids = track_ids[i:i+100]
        params = {'ids': ','.join(batch_ids)}
        response = requests.get('https://api.spotify.com/v1/audio-features', headers=headers, params=params)
        if response.status_code == 200:
            audio_features.extend(response.json()['audio_features'])
        elif response.status_code == 401:
            if refresh_access_token(user):
                headers['Authorization'] = f'Bearer {user.access_token}'
                response = requests.get('https://api.spotify.com/v1/audio-features', headers=headers, params=params)
                if response.status_code == 200:
                    audio_features.extend(response.json()['audio_features'])
                else:
                    logger.error(f"Failed to fetch audio features after token refresh for user {user.username}: {response.status_code} {response.text}")
                    flash(f"Failed to fetch audio features for user {user.username}.")
            else:
                logger.error(f"Failed to refresh token for user {user.username} when fetching audio features.")
                flash(f"Failed to refresh access token for user {user.username}.")
        else:
            logger.error(f"Error fetching audio features for user {user.username}: {response.status_code} {response.text}")
            flash(f"Error fetching audio features for user {user.username}.")
    return audio_features

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login')
def login():
    scope = 'user-top-read'
    auth_url = (
        'https://accounts.spotify.com/authorize'
        f'?client_id={client_id}'
        '&response_type=code'
        f'&redirect_uri={redirect_uri}'
        f'&scope={scope}'
    )
    return redirect(auth_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    error = request.args.get('error')
    if error:
        flash(f"Error during authentication: {error}")
        logger.error(f"Authentication error: {error}")
        return redirect(url_for('home'))

    # Exchange code for access token
    token_url = 'https://accounts.spotify.com/api/token'
    payload = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
    }

    client_creds = f"{client_id}:{client_secret}"
    client_creds_b64 = base64.b64encode(client_creds.encode())

    headers = {
        'Authorization': f'Basic {client_creds_b64.decode()}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    response = requests.post(token_url, data=payload, headers=headers)
    response_data = response.json()

    logger.info(f"Token exchange response: {response_data}")

    if 'access_token' in response_data:
        access_token = response_data['access_token']
        refresh_token = response_data.get('refresh_token')

        # Use the access token to access Spotify API
        headers = {
            'Authorization': f'Bearer {access_token}'
        }

        # Fetch user's profile information
        user_profile_url = 'https://api.spotify.com/v1/me'
        profile_response = requests.get(user_profile_url, headers=headers)
        logger.info(f"Profile fetch response status: {profile_response.status_code}")
        logger.info(f"Profile fetch response data: {profile_response.text}")

        if profile_response.status_code != 200:
            logger.error(f"Failed to fetch user profile: {profile_response.status_code} {profile_response.text}")
            flash("Failed to fetch user profile from Spotify.")
            return redirect(url_for('home'))

        profile_data = profile_response.json()

        spotify_id = profile_data['id']
        username = profile_data.get('display_name', spotify_id)
        profile_image = profile_data['images'][0]['url'] if profile_data.get('images') else None

        # Check if user exists
        user = User.query.filter_by(spotify_id=spotify_id).first()
        if not user:
            # Create new user
            user = User(
                spotify_id=spotify_id,
                username=username,
                profile_image=profile_image,
                access_token=access_token,
                refresh_token=refresh_token
            )
            db.session.add(user)
            db.session.commit()
            logger.info(f"New user created: {username}")
        else:
            # Update user tokens and info
            user.access_token = access_token
            user.refresh_token = refresh_token
            user.username = username
            user.profile_image = profile_image
            db.session.commit()
            logger.info(f"Existing user updated: {username}")

        # Log the user in
        login_user(user)
        flash("Successfully logged in.")
        return redirect(url_for('dashboard'))

    else:
        error_message = response_data.get('error_description', 'Unknown error')
        logger.error(f"Authentication failed: {error_message}")
        flash(f"Error: {error_message}")
        return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        top_artists = get_user_top_artists(current_user)
        top_tracks = get_user_top_tracks(current_user)
        return render_template('dashboard.html', user=current_user, top_artists=top_artists, top_tracks=top_tracks)
    except Exception as e:
        logger.error(f"Error in dashboard for user {current_user.username}: {e}")
        flash("An error occurred while loading the dashboard.")
        return redirect(url_for('home'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for('home'))

@app.route('/users')
@login_required
def users():
    try:
        all_users = User.query.filter(User.id != current_user.id, User.share_data == True).all()
        return render_template('users.html', users=all_users)
    except Exception as e:
        logger.error(f"Error fetching users for comparison: {e}")
        flash("An error occurred while fetching users.")
        return redirect(url_for('dashboard'))

@app.route('/compare/<int:user_id>')
@login_required
def compare(user_id):
    try:
        other_user = User.query.get_or_404(user_id)
        if not other_user.share_data:
            flash('The user has disabled data sharing.')
            return redirect(url_for('users'))

        # Fetch top tracks for both users
        current_user_tracks = get_user_top_tracks(current_user)
        other_user_tracks = get_user_top_tracks(other_user)

        # Get audio features
        current_user_audio_features = get_tracks_audio_features(current_user, current_user_tracks)
        other_user_audio_features = get_tracks_audio_features(other_user, other_user_tracks)

        # Define the features to consider
        features = ['danceability', 'energy', 'valence', 'tempo', 'acousticness', 'instrumentalness', 'liveness', 'speechiness']

        # Compute average features for each user
        def average_features(audio_features_list):
            feature_values = {feature: [] for feature in features}
            for af in audio_features_list:
                if af:  # Check if audio feature data is available
                    for feature in features:
                        feature_values[feature].append(af.get(feature, 0))
            avg_features = [np.mean(feature_values[feature]) if feature_values[feature] else 0 for feature in features]
            return np.array(avg_features).reshape(1, -1)

        current_user_avg_features = average_features(current_user_audio_features)
        other_user_avg_features = average_features(other_user_audio_features)

        # Calculate cosine similarity
        audio_similarity = cosine_similarity(current_user_avg_features, other_user_avg_features)[0][0] * 100

        # Fetch top artists for both users
        current_user_artists = get_user_top_artists(current_user)
        other_user_artists = get_user_top_artists(other_user)

        current_user_artist_ids = {artist['id'] for artist in current_user_artists}
        other_user_artist_ids = {artist['id'] for artist in other_user_artists}

        common_artist_ids = current_user_artist_ids & other_user_artist_ids

        # Fetch artist details for common artists
        common_artists = [artist for artist in current_user_artists if artist['id'] in common_artist_ids]

        # Fetch top tracks for both users
        current_user_track_ids = {track['id'] for track in current_user_tracks}
        other_user_track_ids = {track['id'] for track in other_user_tracks}

        common_track_ids = current_user_track_ids & other_user_track_ids

        common_tracks = [track for track in current_user_tracks if track['id'] in common_track_ids]

        # Calculate similarity scores
        artist_similarity = (len(common_artist_ids) / len(current_user_artist_ids)) * 100 if current_user_artist_ids else 0
        track_similarity = (len(common_track_ids) / len(current_user_track_ids)) * 100 if current_user_track_ids else 0

        # Collect genres from common artists
        genres = []
        for artist in common_artists:
            genres.extend(artist['genres'])
        genre_counts = Counter(genres)
        top_genres = genre_counts.most_common(10)  # Top 10 genres

        return render_template(
            'comparison.html',
            other_user=other_user,
            common_artists=common_artists,
            common_tracks=common_tracks,
            artist_similarity=artist_similarity,
            track_similarity=track_similarity,
            audio_similarity=audio_similarity,
            top_genres=top_genres
        )
    except Exception as e:
        logger.error(f"Error during comparison between {current_user.username} and user_id {user_id}: {e}")
        flash("An error occurred while comparing profiles.")
        return redirect(url_for('users'))

@app.route('/update_privacy', methods=['GET', 'POST'])
@login_required
def update_privacy():
    try:
        form = PrivacyForm()
        if form.validate_on_submit():
            current_user.share_data = form.share_data.data
            db.session.commit()
            flash('Privacy settings updated.')
            return redirect(url_for('dashboard'))
        elif request.method == 'GET':
            form.share_data.data = current_user.share_data
        return render_template('update_privacy.html', form=form)
    except Exception as e:
        logger.error(f"Error updating privacy settings for user {current_user.username}: {e}")
        flash("An error occurred while updating privacy settings.")
        return redirect(url_for('dashboard'))

# Enforce HTTPS in Production
@app.before_request
def before_request_func():
    # Use app.config["ENV"] instead of app.env
    if not request.is_secure and app.config.get("ENV") == "production":
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)