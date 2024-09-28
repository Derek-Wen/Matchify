# Matchify

**Matchify** is a web application that leverages the Spotify API to allow users to visualize and compare their top artists and tracks. Users can log in with their Spotify accounts, view their personal music preferences, and compare them with other users in the Matchify community. The application emphasizes user privacy, enabling users to control whether their data can be shared for comparisons.

## Table of Contents

- [Features](#features)
- [Demo](#demo)
- [Technologies Used](#technologies-used)
- [Contact](#contact)

---

## Features

- **Spotify Authentication:** Securely log in using Spotify accounts via OAuth 2.0.
- **Personal Dashboard:** View your top 16 artists and top 16 tracks based on different time ranges (Last 4 Weeks, Last 6 Months, Several Years).
- **User Comparisons:** Compare your music preferences with other users in the Matchify community.
- **Privacy Controls:** Decide whether to allow other users to compare with your music data.
- **Responsive Design:** Accessible and visually appealing on various devices and screen sizes.
- **Custom Domain Support:** Professional appearance with the option to use a custom domain.
- **Secure Data Handling:** Implements best practices for security, including HTTPS enforcement and secure session management.

---

## Demo
[Matchify](https://matchify-b1a89524dd48.herokuapp.com/)

---

## Technologies Used

- **Backend:**
  - [Flask](https://flask.palletsprojects.com/) - Web framework
  - [Flask-Login](https://flask-login.readthedocs.io/) - User session management
  - [Flask-WTF](https://flask-wtf.readthedocs.io/) - Form handling and CSRF protection
  - [Flask-Bcrypt](https://flask-bcrypt.readthedocs.io/) - Password hashing
  - [Flask-Migrate](https://flask-migrate.readthedocs.io/) - Database migrations
  - [SQLAlchemy](https://www.sqlalchemy.org/) - ORM for database interactions
  - [Requests](https://docs.python-requests.org/) - HTTP requests
  - [Python Dotenv](https://pypi.org/project/python-dotenv/) - Environment variable management
  - [Logging](https://docs.python.org/3/library/logging.html) - Application logging

- **Frontend:**
  - [Bootstrap 4](https://getbootstrap.com/) - Responsive UI framework
  - [Chart.js](https://www.chartjs.org/) - Data visualization
  - HTML5 & CSS3 - Markup and styling
  - JavaScript - Interactive features

- **Deployment:**
  - [Heroku](https://www.heroku.com/) - Cloud platform for deployment
  - [Git](https://git-scm.com/) - Version control
  - [GitHub](https://github.com/) - Repository hosting

- **Others:**
  - [Spotify API](https://developer.spotify.com/documentation/web-api/) - Music data access

---

## Contact

  - Derek Wen
  - Email: derek.hz.wen@gmail.com
  - GitHub: @Derek-Wen
  - LinkedIn: https://www.linkedin.com/in/derek-h-wen/
