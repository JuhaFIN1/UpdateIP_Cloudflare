# UpdateIP - Copyright (c) 2026 Juha Lempiäinen. All rights reserved.
# https://github.com/JuhaFIN1/Updateip

import os
import secrets

APP_VERSION = '0.85 beta'

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
SQLALCHEMY_DATABASE_URI = os.path.join(BASE_DIR, 'updateip.db')
SCHEDULER_API_ENABLED = False
