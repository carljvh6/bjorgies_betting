import modal
from modal import asgi_app
from fasthtml.common import *
from monsterui.all import *
from passlib.hash import pbkdf2_sha256
from google.cloud import bigquery
from datetime import datetime
import os
from loguru import logger 

# Create FastHTML app first
fasthtml_app, rt = fast_app(
    hdrs=Theme.blue.headers(),
    secret_key="your-secret-key-here"  # Change this in production
)

def get_bigquery_client():
    """Get authenticated BigQuery client using Modal secret"""
    import json
    from google.oauth2 import service_account
    
    credentials_json = json.loads(os.environ["GOOGLE_APPLICATION_CREDENTIALS_JSON"])
    credentials = service_account.Credentials.from_service_account_info(credentials_json)
    return bigquery.Client(credentials=credentials)

# def query_user(email):
#     """Query user by email from BigQuery."""
#     try:
#         print(f"Attempting to query user with email: {email}")
        
#         # Verify credentials exist
#         if "GOOGLE_APPLICATION_CREDENTIALS_JSON" not in os.environ:
#             print("GOOGLE_APPLICATION_CREDENTIALS_JSON not found in environment")
#             return None

#         client = get_bigquery_client()
#         print("BigQuery client created successfully")
        
#         query = """
#         SELECT * FROM `bjorgies-betting.database.users`
#         WHERE email = @email
#         """
#         job_config = bigquery.QueryJobConfig(
#             query_parameters=[
#                 bigquery.ScalarQueryParameter("email", "STRING", email)
#             ]
#         )
        
#         # Execute query and get results
#         query_job = client.query(query, job_config=job_config)
#         results = query_job.result()  # This gets the actual results
        
#         # Convert to list and get first item if exists
#         rows = list(results)
#         print(f"Query returned {len(rows)} rows")
        
#         if not rows:
#             print(f"No user found with email: {email}")
#             return None
            
#         # Convert row to dict for easier handling
#         row = rows[0]
#         user_dict = {
#             'id': row.get('id'),
#             'username': row.get('username'),
#             'email': row.get('email'),
#             'password_hash': row.get('password_hash'),
#             'approved': row.get('approved', False),
#             'balance': row.get('balance'),
#             'created_at': row.get('created_at')
#         }
        
#         print(f"User found: {user_dict}")
#         return user_dict
    
#     except Exception as e:
#         print(f"Failed to query user: {e}")
#         return None

def query_user_by_username(username):
    """Query user by username from BigQuery."""
    try:
        print(f"Attempting to query user with username: {username}")
        
        # Verify credentials exist
        if "GOOGLE_APPLICATION_CREDENTIALS_JSON" not in os.environ:
            print("GOOGLE_APPLICATION_CREDENTIALS_JSON not found in environment")
            return None

        client = get_bigquery_client()
        print("BigQuery client created successfully")
        
        query = """
        SELECT * FROM `bjorgies-betting.database.users`
        WHERE username = @username
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("username", "STRING", username)
            ]
        )
        
        # Execute query and get results
        query_job = client.query(query, job_config=job_config)
        results = query_job.result()  # This gets the actual results
        
        # Convert to list and get first item if exists
        rows = list(results)
        print(f"Query returned {len(rows)} rows")
        
        if not rows:
            print(f"No user found with username: {username}")
            return None
            
        # Convert row to dict for easier handling
        row = rows[0]
        user_dict = {
            'id': row.get('id'),
            'username': row.get('username'),
            'email': row.get('email'),
            'password_hash': row.get('password_hash'),
            'approved': row.get('approved', False),
            'balance': row.get('balance'),
            'created_at': row.get('created_at')
        }
        
        print(f"User found: {user_dict}")
        return user_dict
    
    except Exception as e:
        print(f"Failed to query user: {e}")
        return None

def insert_user(username, email, password):
    """Insert a new user into BigQuery."""
    client = get_bigquery_client()
    table_id = 'bjorgies-betting.database.users'
    
    # Get max id
    query = "SELECT MAX(id) as max_id FROM `bjorgies-betting.database.users`"
    query_job = client.query(query)
    results = query_job.result()
    row = next(results)
    max_id = row.max_id if row.max_id is not None else 0
    
    # Prepare new user data
    new_user = {
        'id': max_id + 1,
        'username': username,
        'email': email,
        'password_hash': pbkdf2_sha256.hash(password),
        'created_at': datetime.utcnow().isoformat(),
        'approved': False,
        'balance': 1000.0
    }
    
    errors = client.insert_rows_json(table_id, [new_user])
    if errors:
        log.error(f"Errors inserting new user: {errors}")
        raise Exception("Failed to create user")
    return new_user

def auth_error(message):
    """Show error message and redirect to login."""
    return Alert(message, cls=AlertT.error)

@rt("/")
def get():
    """Home page with login/signup options."""
    return Titled("BJorgies Betting",
        Container(
            Div(id="main-content")(
                Card(
                    H2("Welcome to BJorgies Betting"),
                    P("Please login or create a new account to continue."),
                    DivFullySpaced(
                        Button("Login", cls=ButtonT.primary, hx_get="/login", hx_target="#main-content"),
                        Button("Sign Up", cls=ButtonT.secondary, hx_get="/signup", hx_target="#main-content")
                    ),
                    cls="max-w-md mx-auto mt-10"
                )
            )
        )
    )

@rt("/login")
def get():
    """Login page."""
    return Titled("Login",
        Container(
            Div(id="main-content")(
                Card(
                    H3("Login"),
                    Form(
                        LabelInput("Username", type="text", id="username", name="username", required=True),
                        LabelInput("Password", type="password", id="password", name="password", required=True),
                        DivRAligned(
                            Button("Login", type="submit", cls=ButtonT.primary),
                            Button("Back", hx_get="/", cls=ButtonT.ghost, hx_target="#main-content")
                        ),
                        hx_post="/login",
                        hx_target="#message"
                    ),
                    cls="max-w-md mx-auto mt-10"
                ),
                Div(id="message")
            )
        )
    )

@rt("/login")
def post(username: str, password: str, session):
    """Handle login form submission."""
    try:
        # Log all incoming parameters
        print(f"Login attempt - Username: {username}")
        
        # Query user with explicit error handling
        user = query_user_by_username(username)

        if not user:
            print(f"No user found for username: {username}")
            return Div(
                Alert("Invalid username or password", cls=AlertT.error), 
                id="message"
            )
        
        # Password verification
        password_match = pbkdf2_sha256.verify(password, user['password_hash'])
        print(f"Password verification result: {password_match}")

        if not password_match:
            print("Password does not match")
            return Div(
                Alert("Invalid username or password", cls=AlertT.error), 
                id="message"
            )
            
        if not user.get('approved', False):
            print("Account not approved")
            return Div(
                Alert("Your account is pending approval", cls=AlertT.warning), 
                id="message"
            )

        # Set session
        session['user_id'] = user['id']
        session['username'] = user['username']
        
        # Explicitly create a response with HX headers
        response = Div(
            Alert("Login successful!", cls=AlertT.success),
            # Explicitly set HX headers for redirection
            Script("""
            setTimeout(() => {
                htmx.ajax('GET', '/dashboard', '#main-content');
            }, 1000);
            """)
        )
        return response

    except Exception as e:
        print(f"Unexpected login error: {e}")
        return Div(
            Alert(f"An unexpected error occurred: {str(e)}", cls=AlertT.error), 
            id="message"
        )

@rt("/signup")
def get():
    return Titled("Sign Up",
        Container(
            Card(
                H3("Create Account"),
                Form(
                    LabelInput("Username", id="username", name="username", required=True),  # Added name
                    LabelInput("Email", type="email", id="email", name="email", required=True),  # Added name
                    LabelInput("Password", type="password", id="password", name="password", required=True),  # Added name
                    DivRAligned(
                        Button("Sign Up", type="submit", cls=ButtonT.primary),
                        Button("Back", hx_get="/", cls=ButtonT.ghost)
                    ),
                    hx_post="/signup",
                    hx_swap="outerHTML"  # Add this
                ),
                cls="max-w-md mx-auto mt-10"
            ),
            Div(id="message")
        )
    )

@rt("/signup")
def post(username: str, email: str, password: str):
    """Handle signup form submission."""
    try:
        # Check if user exists
        if query_user(email):
            return auth_error("Email already registered")
        
        # Create new user
        insert_user(username, email, password)
        
        return Alert(
            "Account created successfully! Please wait for admin approval.",
            cls=AlertT.success
        )
    except Exception as e:
        log.error(f"Signup error: {e}")
        return auth_error("Failed to create account. Please try again.")

@rt("/dashboard")
def get(session):
    """Dashboard page - requires login."""
    if 'user_id' not in session:
        return RedirectResponse('/login', status_code=303)
        
    return Titled(f"Welcome {session['username']}",
        Container(
            Div(id="main-content")(
                Card(
                    H2("Dashboard"),
                    P("Welcome to your betting dashboard. Coming soon!"),
                    Button("Logout", hx_post="/logout", cls=ButtonT.ghost),
                    cls="mt-10"
                )
            )
        )
    )

@rt("/logout")
def post(session):
    """Handle logout."""
    session.clear()
    response = RedirectResponse('/', status_code=303)
    response.headers['HX-Redirect'] = '/'
    return response

# Modal setup
app = modal.App()

@app.function(
    image=modal.Image.debian_slim().pip_install(
        "python-fasthtml", 
        "google-cloud-bigquery", 
        "passlib", 
        "loguru",
        "MonsterUI"
    ),
    secrets=[modal.Secret.from_name("google-cloud-creds")]
)
@asgi_app()
def fasthtml_asgi():
    return fasthtml_app

if __name__ == "__main__":
    modal.serve(fasthtml_asgi)