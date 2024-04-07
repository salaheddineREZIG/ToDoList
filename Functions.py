from email_validator import validate_email, EmailNotValidError
from flask import flash

def validate(email):
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        flash("Invalid email format", "error")
        return False



