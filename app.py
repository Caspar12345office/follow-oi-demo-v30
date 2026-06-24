
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, Response
from werkzeug.utils import secure_filename
import sqlite3, os, csv, io, secrets, random, html, smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage

DB_PATH = "follow_oi.db"
UPLOAD_FOLDER = "uploads"

app = Flask(__name__)
app.secret_key = "change-this-secret-key"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ACCOUNT_REQUEST_EMAIL = os.environ.get("FOLLOW_OI_ACCOUNT_REQUEST_EMAIL", "caspar@office-interior.nl")

def send_account_request_email(data):
    """Send account request by SMTP when configured. Always returns a status string."""
    host = os.environ.get("SMTP_HOST")
    username = os.environ.get("SMTP_USERNAME")
    password = os.environ.get("SMTP_PASSWORD")
    sender = os.environ.get("SMTP_FROM", username or ACCOUNT_REQUEST_EMAIL)
    port = int(os.environ.get("SMTP_PORT", "587"))
    if not host or not username or not password:
        return "opgeslagen"
    msg = EmailMessage()
    msg["Subject"] = f"Nieuwe accountaanvraag Follow O-I - {data.get('company_name') or data.get('email')}"
    msg["From"] = sender
    msg["To"] = ACCOUNT_REQUEST_EMAIL
    msg.set_content("\n".join([
        "Nieuwe accountaanvraag via Follow O-I",
        "",
        f"Naam: {data.get('first_name','')} {data.get('last_name','')}",
        f"Bedrijf: {data.get('company_name','')}",
        f"Functie: {data.get('job_title','')}",
        f"E-mail: {data.get('email','')}",
        f"Telefoon: {data.get('phone','')}",
        f"Type organisatie: {data.get('organisation_type','')}",
        "",
        "Bericht:",
        data.get('message','') or '-',
        "",
        f"Ontvangen op: {now()}"
    ]))
    try:
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.starttls()
            smtp.login(username, password)
            smtp.send_message(msg)
        return "per e-mail verzonden"
    except Exception:
        return "opgeslagen"


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M")

def today():
    return datetime.now().strftime("%Y-%m-%d")


def future_minutes(minutes):
    return (datetime.now() + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M")

def parse_dt(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M") if value else None
    except Exception:
        return None

PERMISSION_KEYS = [
    "view_dashboard","view_clients","edit_clients","view_assets","edit_assets",
    "view_orders","edit_orders","view_damages","edit_damages",
    "view_documents","upload_documents","view_impact","view_marketplace","view_rfid","manage_rfid",
    "view_marketplace","view_emvi","manage_users"
]

ROLE_DEFAULTS = {
    "admin": PERMISSION_KEYS,
    "staff": ["view_dashboard","view_clients","edit_clients","view_assets","edit_assets","view_orders","edit_orders","view_damages","edit_damages","view_documents","upload_documents","view_impact","view_marketplace","view_rfid","manage_rfid","view_marketplace","view_emvi"],
    "client_admin": ["view_dashboard","view_assets","view_orders","edit_orders","view_damages","edit_damages","view_documents","upload_documents","view_impact","view_marketplace"],
    "client_user": ["view_dashboard","view_assets","view_orders","view_damages","edit_damages","view_documents","view_impact","view_marketplace"]
}

def get_permissions(user_id):
    conn = db(); rows = conn.execute("SELECT permission FROM user_permissions WHERE user_id=?", (user_id,)).fetchall(); conn.close()
    return set(r["permission"] for r in rows)

def has_perm(permission):
    u = current_user()
    if not u: return False
    if u["role"] == "admin": return True
    return permission in get_permissions(u["id"])

def require_perm(permission):
    if not require_login():
        return redirect(url_for("login"))
    if not has_perm(permission):
        return render_template("no_access.html", permission=permission), 403
    return None

def set_permissions(user_id, permissions):
    conn = db(); conn.execute("DELETE FROM user_permissions WHERE user_id=?", (user_id,))
    for p in permissions:
        if p in PERMISSION_KEYS:
            conn.execute("INSERT INTO user_permissions (user_id, permission) VALUES (?,?)", (user_id, p))
    conn.commit(); conn.close()

def create_otp(user_id):
    code = f"{random.randint(100000,999999)}"
    conn = db(); conn.execute("INSERT INTO user_otps (user_id, code, expires_at, used, created_at) VALUES (?,?,?,?,?)", (user_id, code, future_minutes(10), 0, now())); conn.commit(); conn.close()
    return code

def log_event(user_id, event, details=""):
    conn = db(); conn.execute("INSERT INTO audit_log (user_id,event,details,created_at) VALUES (?,?,?,?)", (user_id, event, details, now())); conn.commit(); conn.close()

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


PRODUCT_SEED = [
    ("OI-DESK-FUSE", "Elektrisch zit-sta bureau Fuse", "Zit-sta bureaus", "Elektrisch zit-sta bureau voor ergonomische werkplekken, flexplekken en hybride kantoren.", "Vanaf 344,85 incl. BTW", "", "https://office-interior.com/nl/products/elektrisch-zit-sta-bureau-fuse", "bureau,zit-sta,ergonomie,werkplek"),
    ("OI-CHAIR-ONYX", "Bureaustoel Renab Onyx - NPR 1813", "Bureaustoelen", "Ergonomische bureaustoel voor professionele werkplekken.", "363,00 incl. BTW", "", "https://office-interior.com/nl/products/bureaustoel-renab-onyx-npr-1813", "bureaustoel,ergonomie,npr,werkplek"),
    ("OI-DESK-AERO", "Elektrisch zit-sta bureau Aero - NEN-EN 527", "Zit-sta bureaus", "Elektrisch zit-sta bureau met stille motoren, geheugenbediening en professionele normering.", "Vanaf 484,00 incl. BTW", "", "https://office-interior.com/nl/products/elektrisch-zit-sta-bureau-aero", "bureau,zit-sta,nen,ergonomie"),
    ("OI-CHAIR-MAST", "Bureaustoel Renab Mast Black", "Bureaustoelen", "Zwarte ergonomische bureaustoel voor moderne kantooromgevingen.", "272,25 incl. BTW", "", "https://office-interior.com/nl/products/bureaustoel-renab-mast-black", "bureaustoel,zwart,ergonomie"),
    ("OI-CAB-ROSA", "Kast met plantenbak Rosa", "Kantoorkasten", "Kast met geintegreerde plantenbak voor groen, rust en opbergruimte in de werkomgeving.", "Offerte op aanvraag", "", "https://office-interior.com/nl/products/cabinet-with-a-plant-box-rosa", "kast,plantenbak,groen,opbergen"),
    ("OI-MEET-ELLIPSE", "Vergadertafel Ellipse", "Vergadertafels", "Representatieve ovale vergadertafel voor moderne vergaderruimtes.", "Offerte op aanvraag", "", "https://office-interior.com/nl/products/vergadertafel-ellipse", "vergadertafel,meeting,ovaal"),
    ("OI-MEET-X", "Vergadertafel X", "Vergadertafels", "Vergadertafel voor moderne vergader- en projectruimtes.", "Offerte op aanvraag", "", "https://office-interior.com/nl/products/vergadertafel-x", "vergadertafel,meeting"),
    ("OI-MEET-DANISH", "Vergadertafel Deens ovaal", "Vergadertafels", "Deens ovale vergadertafel voor representatieve overlegplekken.", "Offerte op aanvraag", "", "https://office-interior.com/nl/products/vergadertafel", "vergadertafel,deens ovaal"),
    ("OI-CHAIR-LIO", "Renab Lio", "Vergaderstoelen", "Comfortabele vergaderstoel met eigentijdse uitstraling.", "Offerte op aanvraag", "", "https://office-interior.com/nl/products/renab-lio", "vergaderstoel,stoel,renab"),
    ("OI-CHAIR-JAX", "Renab Jax", "Vergaderstoelen", "Stoel met zwart metalen frame, houten details en bekleding van gerecycled polyester.", "Offerte op aanvraag", "", "https://office-interior.com/nl/products/renab-jax", "vergaderstoel,stoel,recycled"),
    ("OI-CHAIR-VERA", "Renab Vera", "Stoelen", "Stoel voor moderne kantoor- en hospitalityruimtes.", "Offerte op aanvraag", "", "https://office-interior.com/nl/products/renab-vera", "stoel,renab,hospitality"),
    ("OI-CHAIR-NOVA", "Renab Nova", "Stoelen", "Stoel voor kantoorinrichting en projectomgevingen.", "Offerte op aanvraag", "", "https://office-interior.com/nl/products/renab-nova", "stoel,renab"),
    ("OI-CHAIR-BRUNO", "Renab Bruno", "Stoelen", "Stoel voor zakelijke interieurs.", "Offerte op aanvraag", "", "https://office-interior.com/nl/products/renab-bruno", "stoel,renab"),
    ("OI-DESK-NOW", "Verstelbaar bureau Now", "Verstelbare bureaus", "Verstelbaar bureau met lichte uitstraling en hoogteverstelling.", "Offerte op aanvraag", "", "https://office-interior.com/nl/products/instelbaar-bureau-now", "bureau,verstelbaar,werkplek"),
    ("OI-LOCKER", "Lockerkast projectinrichting", "Lockers", "Lockers voor persoonlijke opslag in kantoor-, onderwijs- en hospitalityomgevingen.", "Offerte op aanvraag", "", "", "locker,opslag,kast"),
    ("OI-ACOUSTIC", "Akoestische oplossing kantoor", "Akoestiek", "Akoestische oplossingen voor focusplekken, overlegzones en open kantoorvloeren.", "Offerte op aanvraag", "", "", "akoestiek,focus,privacy"),
]

def seed_products():
    conn = db()
    count = conn.execute("SELECT COUNT(*) c FROM products").fetchone()["c"]
    if count == 0:
        for sku, name, category, description, price_text, image_url, source_url, tags in PRODUCT_SEED:
            conn.execute("""INSERT INTO products
                            (sku,name,category,description,price_text,image_url,source_url,tags,active,created_at)
                            VALUES (?,?,?,?,?,?,?,?,?,?)""",
                         (sku, name, category, description, price_text, image_url, source_url, tags, 1, now()))
        conn.commit()
    conn.close()


def make_rfid(client_name, asset_code):
    client_code = "".join([c for c in client_name.upper() if c.isalnum()])[:4] or "KLNT"
    suffix = "".join([c for c in asset_code.upper() if c.isalnum()])[-6:] or str(int(datetime.now().timestamp()))
    return f"RFID-OI-{client_code}-{suffix}"

def init_db():
    conn = db()
    c = conn.cursor()


    c.execute("""
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sku TEXT,
        name TEXT NOT NULL,
        category TEXT,
        description TEXT,
        price_text TEXT,
        image_url TEXT,
        source_url TEXT,
        tags TEXT,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT,
        role TEXT NOT NULL DEFAULT 'staff',
        password TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        email_verified INTEGER NOT NULL DEFAULT 0,
        two_factor_enabled INTEGER NOT NULL DEFAULT 1,
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT,
        invite_token TEXT,
        created_at TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS user_permissions (
        user_id INTEGER NOT NULL,
        permission TEXT NOT NULL,
        PRIMARY KEY(user_id, permission)
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS user_otps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        code TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        event TEXT NOT NULL,
        details TEXT,
        created_at TEXT NOT NULL
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS account_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT,
        last_name TEXT,
        company_name TEXT,
        job_title TEXT,
        email TEXT,
        phone TEXT,
        organisation_type TEXT,
        message TEXT,
        mail_status TEXT,
        created_at TEXT NOT NULL
    )
    """)
    for sql in [
        "ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE users ADD COLUMN locked_until TEXT",
        "ALTER TABLE users ADD COLUMN language TEXT NOT NULL DEFAULT 'nl'"
    ]:
        try: c.execute(sql)
        except Exception: pass

    c.execute("""
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        contact_name TEXT,
        contact_email TEXT,
        contact_phone TEXT,
        account_manager_name TEXT,
        account_manager_email TEXT,
        account_manager_phone TEXT,
        created_at TEXT NOT NULL
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER NOT NULL,
        asset_code TEXT UNIQUE NOT NULL,
        rfid TEXT UNIQUE NOT NULL,
        category TEXT NOT NULL,
        brand TEXT,
        model TEXT,
        location TEXT,
        room TEXT,
        floor TEXT,
        status TEXT NOT NULL DEFAULT 'in gebruik',
        condition_score INTEGER DEFAULT 4,
        purchase_date TEXT,
        circular_source TEXT,
        co2_kg REAL DEFAULT 0,
        material_kg REAL DEFAULT 0,
        cost_saving_eur REAL DEFAULT 0,
        last_service TEXT,
        created_at TEXT NOT NULL
    )
    """)
    for sql in [
        "ALTER TABLE assets ADD COLUMN marketplace_status TEXT NOT NULL DEFAULT 'niet beschikbaar'",
        "ALTER TABLE assets ADD COLUMN marketplace_note TEXT",
        "ALTER TABLE assets ADD COLUMN marketplace_available_from TEXT",
        "ALTER TABLE assets ADD COLUMN marketplace_reserved_by_user_id INTEGER",
        "ALTER TABLE assets ADD COLUMN marketplace_reserved_at TEXT",
        "ALTER TABLE assets ADD COLUMN photo_path TEXT",
        "ALTER TABLE assets ADD COLUMN photo_note TEXT"
    ]:
        try: c.execute(sql)
        except Exception: pass

    c.execute("""
    CREATE TABLE IF NOT EXISTS asset_movements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id INTEGER NOT NULL,
        from_location TEXT,
        from_room TEXT,
        from_floor TEXT,
        to_location TEXT,
        to_room TEXT,
        to_floor TEXT,
        note TEXT,
        moved_at TEXT NOT NULL,
        created_by_user_id INTEGER,
        created_at TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER NOT NULL,
        furniture_type TEXT NOT NULL,
        quantity INTEGER NOT NULL,
        color TEXT,
        quality TEXT,
        delivery_location TEXT,
        room TEXT,
        desired_delivery_date TEXT,
        assembly TEXT,
        note TEXT,
        status TEXT NOT NULL DEFAULT 'offerte aangevraagd',
        created_at TEXT NOT NULL
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS damages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER NOT NULL,
        asset_id INTEGER,
        contact_name TEXT,
        contact_email TEXT,
        contact_phone TEXT,
        location TEXT,
        room TEXT,
        urgency TEXT,
        description TEXT NOT NULL,
        photo_path TEXT,
        status TEXT NOT NULL DEFAULT 'nieuw',
        created_at TEXT NOT NULL
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER NOT NULL,
        asset_id INTEGER,
        created_by_user_id INTEGER,
        contact_name TEXT,
        contact_email TEXT,
        contact_phone TEXT,
        subject TEXT NOT NULL,
        category TEXT,
        priority TEXT NOT NULL DEFAULT 'Middel',
        location TEXT,
        room TEXT,
        message TEXT NOT NULL,
        attachment_path TEXT,
        assigned_to_name TEXT,
        assigned_to_email TEXT,
        status TEXT NOT NULL DEFAULT 'nieuw',
        last_response TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER NOT NULL,
        doc_type TEXT NOT NULL,
        filename TEXT NOT NULL,
        stored_filename TEXT NOT NULL,
        note TEXT,
        created_at TEXT NOT NULL
    )
    """)

    c.execute("SELECT COUNT(*) c FROM users")
    if c.fetchone()["c"] == 0:
        c.execute("""INSERT INTO users (name,email,phone,role,password,active,email_verified,two_factor_enabled,created_at)
                     VALUES (?,?,?,?,?,?,?,?,?)""",
                  ("Caspar Mastenbroek", "caspar@office-interior.nl", "0626983165", "admin", "ChangeMe123!", 1, 1, 1, now()))

    c.execute("SELECT COUNT(*) c FROM clients")
    if c.fetchone()["c"] == 0:
        c.execute("""INSERT INTO clients
                     (name,contact_name,contact_email,contact_phone,account_manager_name,account_manager_email,account_manager_phone,created_at)
                     VALUES (?,?,?,?,?,?,?,?)""",
                  ("TenneT", "Facility Manager", "facility@example.nl", "Algemeen nummer Follow O-I",
                   "Caspar Mastenbroek", "caspar@office-interior.nl", "0626983165", now()))
        client_id = c.lastrowid

        seed = [
            ("OI-000001","RFID-OI-TENN-000001","Bureaustoel","Ahrend","2020","Arnhem HQ","3.12","3","in gebruik",4,"2024-03-18","bestaand",45,28,180,"2026-04-12"),
            ("OI-000002","RFID-OI-TENN-000002","Zit-sta bureau","Gispen","NPR","Arnhem HQ","3.12","3","in gebruik",4,"2023-11-02","bestaand",80,55,320,"2026-02-18"),
            ("OI-000003","RFID-OI-TENN-000003","Vergaderstoel","Vepa","Felt","Arnhem HQ","Meeting 2.05","2","refurbishment",2,"2022-09-14","second-life",25,16,90,"2026-06-02"),
            ("OI-000004","RFID-OI-TENN-000004","Meeting pod","Framery","Q","Arnhem HQ","Focuszone 1","1","in gebruik",5,"2025-01-28","nieuw circulair",160,210,0,"2026-05-23"),
        ]
        for row in seed:
            c.execute("""INSERT INTO assets
                         (client_id,asset_code,rfid,category,brand,model,location,room,floor,status,condition_score,purchase_date,circular_source,co2_kg,material_kg,cost_saving_eur,last_service,created_at)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (client_id, *row, now()))

    # Demo accounts for shared testing on Render/Vercel
    demo_users = [
        ("Demo gebruiker", "demo@followoi.nl", "", "admin", "FollowOI2025!", 1, 1, 0, now()),
        ("Demo gebruiker 2FA", "demo2fa@followoi.nl", "", "admin", "FollowOI2025!", 1, 1, 1, now()),
    ]
    for demo in demo_users:
        existing = c.execute("SELECT id FROM users WHERE email=?", (demo[1],)).fetchone()
        if existing:
            c.execute("UPDATE users SET name=?, role=?, password=?, active=1, email_verified=1, two_factor_enabled=? WHERE email=?",
                      (demo[0], demo[3], demo[4], demo[7], demo[1]))
            demo_id = existing["id"]
        else:
            c.execute("""INSERT INTO users (name,email,phone,role,password,active,email_verified,two_factor_enabled,created_at)
                         VALUES (?,?,?,?,?,?,?,?,?)""", demo)
            demo_id = c.lastrowid
        for perm in PERMISSION_KEYS:
            c.execute("INSERT OR IGNORE INTO user_permissions (user_id, permission) VALUES (?,?)", (demo_id, perm))

    admin = c.execute("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").fetchone()
    if admin:
        cnt = c.execute("SELECT COUNT(*) c FROM user_permissions WHERE user_id=?", (admin["id"],)).fetchone()["c"]
        if cnt == 0:
            for p in PERMISSION_KEYS:
                c.execute("INSERT OR IGNORE INTO user_permissions (user_id, permission) VALUES (?,?)", (admin["id"], p))
    conn.commit()
    conn.close()
    seed_products()

def current_user():
    if "user_id" not in session:
        return None
    conn = db()
    u = conn.execute("SELECT * FROM users WHERE id=? AND active=1", (session["user_id"],)).fetchone()
    conn.close()
    return u

def require_login():
    return current_user() is not None

LANGUAGES = {"nl": "Nederlands", "en": "English"}

@app.context_processor
def inject():
    return {"user": current_user(), "has_perm": has_perm, "PERMISSION_KEYS": PERMISSION_KEYS, "LANGUAGES": LANGUAGES}

@app.route("/settings/language", methods=["GET","POST"])
def language_settings():
    if not require_login(): return redirect(url_for("login"))
    saved = False
    if request.method == "POST":
        language = request.form.get("language", "nl")
        if language not in LANGUAGES:
            language = "nl"
        conn = db()
        conn.execute("UPDATE users SET language=? WHERE id=?", (language, session.get("user_id")))
        conn.commit(); conn.close()
        saved = True
    return render_template("language_settings.html", saved=saved)



EN_TRANSLATIONS = {
    "Follow O-I portal": "Follow O-I portal",
    "Dashboard": "Dashboard",
    "Klanten": "Clients",
    "Meubilair": "Furniture",
    "Huidig meubilair": "Current furniture",
    "Circulaire marketplace": "Circular marketplace",
    "Productcatalogus": "Product catalogue",
    "Offertes": "Quotations",
    "Offerteoverzicht": "Quotation overview",
    "Offerte aanvragen": "Request quotation",
    "Tickets": "Tickets",
    "Ticketoverzicht": "Ticket overview",
    "Ticket aanmaken": "Create ticket",
    "Schade melden": "Report damage",
    "Documenten": "Documents",
    "Impact": "Impact",
    "RFID": "RFID",
    "EMVI": "EMVI",
    "Gebruikers": "Users",
    "Talen": "Languages",
    "Uitloggen": "Log out",
    "Jouw vaste aanspreekpunt": "Your dedicated contact",
    "Sales Director": "Sales Director",
    "Voor algemene vragen of bij afwezigheid van Caspar kun je contact opnemen met Office-Interior algemeen.": "For general questions or when Caspar is unavailable, you can contact Office-Interior general support.",
    "Algemeen": "General",
    "Algemene vragen": "General questions",
    "Taal opgeslagen.": "Language saved.",
    "Kies de gewenste taal voor de gebruiker. De Follow O-I layout en styling blijven ongewijzigd.": "Choose the preferred language for the user. The Follow O-I layout and styling remain unchanged.",
    "Taal": "Language",
    "Nederlands": "Dutch",
    "Opslaan": "Save",
    "Nieuw item plaatsen": "Add new item",
    "Beschikbaar meubilair": "Available furniture",
    "Mijn aanbiedingen": "My listings",
    "Lopende schades": "Open damages",
    "Nieuwe schade melden": "Report new damage",
    "Schademeldingen": "Damage reports",
    "Schade": "Damage",
    "Melden": "Report",
    "Categorie": "Category",
    "Merk": "Brand",
    "Model": "Model",
    "Locatie": "Location",
    "Ruimte": "Room",
    "Verdieping": "Floor",
    "Status": "Status",
    "Conditie": "Condition",
    "Uitgeleverd": "Delivered",
    "Laatste service": "Last service",
    "Aantal": "Quantity",
    "Omschrijving": "Description",
    "Foto": "Photo",
    "Contactpersoon": "Contact person",
    "Beschikbaar vanaf": "Available from",
    "Beschikbaar": "Available",
    "Gereserveerd": "Reserved",
    "Verplaatst": "Moved",
    "Verkocht": "Sold",
    "Klant": "Client",
    "Naam": "Name",
    "E-mail": "Email",
    "Telefoon": "Phone",
    "Prioriteit": "Priority",
    "Onderwerp": "Subject",
    "Bericht": "Message",
    "Bijlage": "Attachment",
    "Laag": "Low",
    "Middel": "Medium",
    "Hoog": "High",
    "nieuw": "new",
    "opgelost": "resolved",
    "gesloten": "closed",
    "in gebruik": "in use",
    "offerte aangevraagd": "quotation requested",
    "Opdrachtgever": "Client",
    "Projecten": "Projects",
    "Meubelbestand": "Furniture inventory",
    "Klantenbeheer": "Client management",
    "Aantal assets": "Number of assets",
    "Open tickets": "Open tickets",
    "Open schades": "Open damages",
    "Acties": "Actions",
    "Bewerken": "Edit",
    "Plaatsen": "Post",
    "Terug": "Back",
    "Bekijk": "View",
}

def _translate_html(html, lang):
    if lang != "en":
        return html
    # Replace longer labels first to avoid partial replacements.
    for nl, en in sorted(EN_TRANSLATIONS.items(), key=lambda item: len(item[0]), reverse=True):
        html = html.replace(nl, en)
    html = html.replace('<html lang="nl">', '<html lang="en">')
    return html

@app.after_request
def apply_language_translation(response):
    try:
        user = current_user()
        if not user or user["language"] != "en":
            return response
        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type or response.direct_passthrough:
            return response
        html = response.get_data(as_text=True)
        response.set_data(_translate_html(html, "en"))
        response.headers["Content-Length"] = str(len(response.get_data()))
    except Exception:
        pass
    return response

@app.route("/login", methods=["GET","POST"])
def login():
    error = ""
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        conn = db()
        user = conn.execute("SELECT * FROM users WHERE email=? AND active=1", (email,)).fetchone()
        if user and user["locked_until"]:
            locked = parse_dt(user["locked_until"])
            if locked and locked > datetime.now():
                conn.close(); return render_template("login.html", error="Account tijdelijk geblokkeerd. Probeer later opnieuw.")
        if user and user["password"] == password:
            conn.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (user["id"],)); conn.commit(); conn.close()
            if not user["email_verified"]:
                return render_template("login.html", error="Bevestig eerst je e-mailadres via de uitnodigingslink.")
            if user["two_factor_enabled"]:
                otp = create_otp(user["id"]); session["pending_2fa_user_id"] = user["id"]; log_event(user["id"], "2FA_CODE_CREATED", "Demo-code op scherm getoond")
                return render_template("login.html", show_2fa=True, demo_code=otp, twofa_email=user["email"])
            session["user_id"] = user["id"]; log_event(user["id"], "LOGIN", "Login zonder 2FA")
            return redirect(url_for("dashboard"))
        if user:
            attempts = (user["failed_attempts"] or 0) + 1
            locked_until = future_minutes(30) if attempts >= 5 else None
            conn.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?", (attempts, locked_until, user["id"])); conn.commit()
        conn.close(); error = "Onjuiste login of account nog niet actief."
    return render_template("login.html", error=error)


@app.route("/account-aanvragen", methods=["POST"])
def account_request():
    data = {
        "first_name": request.form.get("first_name", "").strip(),
        "last_name": request.form.get("last_name", "").strip(),
        "company_name": request.form.get("company_name", "").strip(),
        "job_title": request.form.get("job_title", "").strip(),
        "email": request.form.get("email", "").strip().lower(),
        "phone": request.form.get("phone", "").strip(),
        "organisation_type": request.form.get("organisation_type", "").strip(),
        "message": request.form.get("message", "").strip(),
    }
    required = [data["first_name"], data["last_name"], data["company_name"], data["email"], data["phone"], data["organisation_type"]]
    if not all(required):
        return render_template("login.html", error="Vul alle verplichte velden van de accountaanvraag in.", show_account_request=True, request_form=data)
    mail_status = send_account_request_email(data)
    conn = db()
    conn.execute("""INSERT INTO account_requests
                    (first_name,last_name,company_name,job_title,email,phone,organisation_type,message,mail_status,created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                 (data["first_name"], data["last_name"], data["company_name"], data["job_title"], data["email"], data["phone"], data["organisation_type"], data["message"], mail_status, now()))
    conn.commit(); conn.close()
    return render_template("login.html", request_sent=True, show_account_request=True)

@app.route("/verify-2fa", methods=["POST"])
def verify_2fa():
    user_id = session.get("pending_2fa_user_id")
    if not user_id: return redirect(url_for("login"))
    code = request.form.get("code","").strip()
    conn = db(); otp = conn.execute("SELECT * FROM user_otps WHERE user_id=? AND code=? AND used=0 ORDER BY id DESC LIMIT 1", (user_id, code)).fetchone()
    if not otp:
        conn.close(); return render_template("login.html", show_2fa=True, error="Onjuiste 2FA-code.")
    expires = parse_dt(otp["expires_at"])
    if not expires or expires < datetime.now():
        conn.close(); return render_template("login.html", show_2fa=True, error="Code verlopen. Log opnieuw in.")
    conn.execute("UPDATE user_otps SET used=1 WHERE id=?", (otp["id"],)); conn.commit(); conn.close()
    session.pop("pending_2fa_user_id", None); session["user_id"] = user_id; log_event(user_id, "LOGIN_2FA", "Succesvolle 2FA login")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
def dashboard():
    blocked = require_perm("view_dashboard")
    if blocked: return blocked
    conn = db()
    stats = {
        "clients": conn.execute("SELECT COUNT(*) c FROM clients").fetchone()["c"],
        "assets": conn.execute("SELECT COUNT(*) c FROM assets").fetchone()["c"],
        "orders": conn.execute("SELECT COUNT(*) c FROM orders WHERE status!='afgerond'").fetchone()["c"],
        "damages": conn.execute("SELECT COUNT(*) c FROM damages WHERE status!='opgelost'").fetchone()["c"],
        "tickets": conn.execute("SELECT COUNT(*) c FROM tickets WHERE status!='gesloten'").fetchone()["c"],
        "co2": round(conn.execute("SELECT COALESCE(SUM(co2_kg),0) c FROM assets").fetchone()["c"]),
        "material": round(conn.execute("SELECT COALESCE(SUM(material_kg),0) c FROM assets").fetchone()["c"]),
    }
    recent = conn.execute("""SELECT a.*, c.name client_name FROM assets a JOIN clients c ON c.id=a.client_id
                             ORDER BY a.id DESC LIMIT 8""").fetchall()
    category_summary = conn.execute("""
        SELECT category, COUNT(*) count FROM assets
        GROUP BY category ORDER BY count DESC LIMIT 6
    """).fetchall()
    location_count = conn.execute("SELECT COUNT(DISTINCT location) c FROM assets WHERE location IS NOT NULL AND location!=''").fetchone()["c"]
    conn.close()
    return render_template("dashboard.html", stats=stats, recent=recent, category_summary=category_summary, location_count=location_count)

@app.route("/clients")
def clients():
    blocked = require_perm("view_clients")
    if blocked: return blocked
    conn = db()
    rows = conn.execute("SELECT * FROM clients ORDER BY name").fetchall()
    conn.close()
    return render_template("clients.html", clients=rows)

@app.route("/clients/new", methods=["GET","POST"])
def client_new():
    blocked = require_perm("edit_clients")
    if blocked: return blocked
    if request.method == "POST":
        conn = db()
        conn.execute("""INSERT INTO clients
                        (name,contact_name,contact_email,contact_phone,account_manager_name,account_manager_email,account_manager_phone,created_at)
                        VALUES (?,?,?,?,?,?,?,?)""",
                     (request.form["name"], request.form.get("contact_name"), request.form.get("contact_email"),
                      request.form.get("contact_phone"), request.form.get("account_manager_name"),
                      request.form.get("account_manager_email"), request.form.get("account_manager_phone"), now()))
        conn.commit(); conn.close()
        return redirect(url_for("clients"))
    return render_template("client_form.html")

@app.route("/client/<int:client_id>")
def client_portal(client_id):
    blocked = require_perm("view_clients")
    if blocked: return blocked
    conn = db()
    client = conn.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    assets = conn.execute("SELECT * FROM assets WHERE client_id=? ORDER BY location, room", (client_id,)).fetchall()
    orders = conn.execute("SELECT * FROM orders WHERE client_id=? ORDER BY id DESC", (client_id,)).fetchall()
    damages = conn.execute("SELECT * FROM damages WHERE client_id=? ORDER BY id DESC", (client_id,)).fetchall()
    docs = conn.execute("SELECT * FROM documents WHERE client_id=? ORDER BY id DESC", (client_id,)).fetchall()
    impact = {
        "co2": round(sum([a["co2_kg"] or 0 for a in assets])),
        "material": round(sum([a["material_kg"] or 0 for a in assets])),
        "cost": round(sum([a["cost_saving_eur"] or 0 for a in assets])),
    }
    conn.close()
    impact["trees"] = round(impact["co2"]/20)
    impact["car"] = round(impact["co2"]/0.15) if impact["co2"] else 0
    return render_template("client_portal.html", client=client, assets=assets, orders=orders, damages=damages, docs=docs, impact=impact)

@app.route("/assets")
def assets():
    blocked = require_perm("view_assets")
    if blocked: return blocked
    conn = db()
    rows = conn.execute("""SELECT a.*, c.name client_name FROM assets a JOIN clients c ON c.id=a.client_id
                           ORDER BY c.name, a.asset_code""").fetchall()
    conn.close()
    return render_template("assets.html", assets=rows)

@app.route("/assets/<int:asset_id>", methods=["GET","POST"])
def asset_detail(asset_id):
    blocked = require_perm("view_assets")
    if blocked: return blocked
    conn = db()
    asset = conn.execute("""SELECT a.*, c.name client_name
                            FROM assets a JOIN clients c ON c.id=a.client_id
                            WHERE a.id=?""", (asset_id,)).fetchone()
    if not asset:
        conn.close()
        return redirect(url_for("assets"))
    if request.method == "POST":
        if not has_perm("edit_assets"):
            conn.close()
            return render_template("no_access.html", permission="edit_assets"), 403
        action = request.form.get("action")
        if action == "photo":
            f = request.files.get("asset_photo")
            photo_note = request.form.get("photo_note")
            if f and f.filename:
                safe = secure_filename(f.filename)
                stored = f"asset_{asset_id}_{int(datetime.now().timestamp())}_{safe}"
                f.save(os.path.join(UPLOAD_FOLDER, stored))
                conn.execute("UPDATE assets SET photo_path=?, photo_note=? WHERE id=?", (stored, photo_note, asset_id))
            else:
                conn.execute("UPDATE assets SET photo_note=? WHERE id=?", (photo_note, asset_id))
            conn.commit(); conn.close()
            log_event(session.get("user_id"), "ASSET_PHOTO_UPDATE", f"Asset {asset_id} foto bijgewerkt")
            return redirect(url_for("asset_detail", asset_id=asset_id))
        if action == "move":
            to_location = request.form.get("to_location")
            to_room = request.form.get("to_room")
            to_floor = request.form.get("to_floor")
            note = request.form.get("note")
            conn.execute("""INSERT INTO asset_movements
                            (asset_id,from_location,from_room,from_floor,to_location,to_room,to_floor,note,moved_at,created_by_user_id,created_at)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                         (asset_id, asset["location"], asset["room"], asset["floor"],
                          to_location, to_room, to_floor, note, request.form.get("moved_at") or today(),
                          session.get("user_id"), now()))
            conn.execute("UPDATE assets SET location=?, room=?, floor=? WHERE id=?", (to_location, to_room, to_floor, asset_id))
            conn.commit(); conn.close()
            log_event(session.get("user_id"), "ASSET_MOVE", f"Asset {asset_id} verhuisd")
            return redirect(url_for("asset_detail", asset_id=asset_id))
    movements = conn.execute("""SELECT m.*, u.name created_by_name FROM asset_movements m
                                LEFT JOIN users u ON u.id=m.created_by_user_id
                                WHERE m.asset_id=? ORDER BY m.moved_at DESC, m.id DESC""", (asset_id,)).fetchall()
    conn.close()
    return render_template("asset_detail.html", asset=asset, movements=movements)

@app.route("/assets/new", methods=["GET","POST"])
def asset_new():
    blocked = require_perm("edit_assets")
    if blocked: return blocked
    conn = db()
    clients = conn.execute("SELECT id,name FROM clients ORDER BY name").fetchall()
    if request.method == "POST":
        client_id = request.form["client_id"]
        client_name = conn.execute("SELECT name FROM clients WHERE id=?", (client_id,)).fetchone()["name"]
        asset_code = request.form["asset_code"]
        rfid = request.form.get("rfid") or make_rfid(client_name, asset_code)
        conn.execute("""INSERT INTO assets
                        (client_id,asset_code,rfid,category,brand,model,location,room,floor,status,condition_score,purchase_date,circular_source,co2_kg,material_kg,cost_saving_eur,last_service,created_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (client_id, asset_code, rfid, request.form["category"], request.form.get("brand"), request.form.get("model"),
                      request.form.get("location"), request.form.get("room"), request.form.get("floor"), request.form.get("status"),
                      request.form.get("condition_score") or 4, request.form.get("purchase_date"), request.form.get("circular_source"),
                      request.form.get("co2_kg") or 0, request.form.get("material_kg") or 0, request.form.get("cost_saving_eur") or 0,
                      today(), now()))
        conn.commit(); conn.close()
        return redirect(url_for("assets"))
    conn.close()
    return render_template("asset_form.html", clients=clients)



@app.route("/marketplace")
def marketplace():
    blocked = require_perm("view_assets")
    if blocked: return blocked
    q = request.args.get("q", "").strip()
    client_id = request.args.get("client_id", "").strip()
    status = request.args.get("status", "beschikbaar").strip()
    conn = db()
    clients = conn.execute("SELECT id,name FROM clients ORDER BY name").fetchall()
    sql = """
        SELECT a.*, c.name client_name, u.name reserved_by_name
        FROM assets a
        JOIN clients c ON c.id=a.client_id
        LEFT JOIN users u ON u.id=a.marketplace_reserved_by_user_id
        WHERE COALESCE(a.marketplace_status,'niet beschikbaar') != 'niet beschikbaar'
    """
    params = []
    if q:
        sql += """ AND (a.asset_code LIKE ? OR a.category LIKE ? OR a.brand LIKE ? OR a.model LIKE ?
                    OR a.location LIKE ? OR a.room LIKE ? OR a.marketplace_note LIKE ? OR c.name LIKE ?)"""
        params += [f"%{q}%"] * 8
    if client_id:
        sql += " AND a.client_id=?"
        params.append(client_id)
    if status:
        sql += " AND a.marketplace_status=?"
        params.append(status)
    sql += " ORDER BY c.name, a.location, a.room, a.category"
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return render_template("marketplace.html", rows=rows, clients=clients, q=q, selected_client_id=client_id, selected_status=status)


@app.route("/marketplace/new", methods=["GET","POST"])
def marketplace_new():
    if not require_login(): return redirect(url_for("login"))
    conn = db()
    clients = conn.execute("SELECT id,name FROM clients ORDER BY name").fetchall()
    if request.method == "POST":
        client_id = request.form["client_id"]
        client_name = conn.execute("SELECT name FROM clients WHERE id=?", (client_id,)).fetchone()["name"]
        asset_code = f"OI-MP-{int(datetime.now().timestamp())}"
        rfid = request.form.get("rfid") or make_rfid(client_name, asset_code)

        photo_path = None
        photo = request.files.get("marketplace_photo")
        if photo and photo.filename:
            safe = secure_filename(photo.filename)
            photo_path = f"marketplace_{int(datetime.now().timestamp())}_{safe}"
            photo.save(os.path.join(UPLOAD_FOLDER, photo_path))

        conn.execute("""INSERT INTO assets
                        (client_id,asset_code,rfid,category,brand,model,location,room,floor,status,condition_score,purchase_date,circular_source,co2_kg,material_kg,cost_saving_eur,last_service,marketplace_status,marketplace_note,marketplace_available_from,photo_path,created_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (client_id, asset_code, rfid, request.form["category"], request.form.get("brand"), request.form.get("model"),
                      request.form.get("location"), request.form.get("room"), request.form.get("floor"), "beschikbaar voor hergebruik",
                      request.form.get("condition_score") or 4, request.form.get("purchase_date"), "herplaatsing",
                      0, 0, 0,
                      today(), "beschikbaar", request.form.get("marketplace_note"), request.form.get("marketplace_available_from") or today(), photo_path, now()))
        conn.commit()
        log_event(session.get("user_id"), "MARKETPLACE_CREATE", f"Nieuw marketplace item {asset_code}")
        conn.close()
        return redirect(url_for("marketplace"))
    conn.close()
    return render_template("marketplace_new.html", clients=clients)

@app.route("/assets/<int:asset_id>/marketplace", methods=["GET","POST"])
def asset_marketplace_edit(asset_id):
    blocked = require_perm("edit_assets")
    if blocked: return blocked
    conn = db()
    asset = conn.execute("""SELECT a.*, c.name client_name FROM assets a JOIN clients c ON c.id=a.client_id WHERE a.id=?""", (asset_id,)).fetchone()
    if not asset:
        conn.close()
        return redirect(url_for("assets"))
    if request.method == "POST":
        marketplace_status = request.form.get("marketplace_status") or "niet beschikbaar"
        if marketplace_status not in ["niet beschikbaar", "beschikbaar", "gereserveerd"]:
            marketplace_status = "niet beschikbaar"
        reserved_by = None
        reserved_at = None
        if marketplace_status == "gereserveerd":
            reserved_by = asset["marketplace_reserved_by_user_id"] or session.get("user_id")
            reserved_at = asset["marketplace_reserved_at"] or now()
        conn.execute("""UPDATE assets
                        SET marketplace_status=?, marketplace_note=?, marketplace_available_from=?,
                            marketplace_reserved_by_user_id=?, marketplace_reserved_at=?
                        WHERE id=?""",
                     (marketplace_status, request.form.get("marketplace_note"), request.form.get("marketplace_available_from"),
                      reserved_by, reserved_at, asset_id))
        conn.commit(); conn.close()
        log_event(session.get("user_id"), "MARKETPLACE_UPDATE", f"Asset {asset_id} status {marketplace_status}")
        return redirect(url_for("assets"))
    conn.close()
    return render_template("asset_marketplace_form.html", asset=asset)

@app.route("/marketplace/<int:asset_id>/reserve", methods=["POST"])
def marketplace_reserve(asset_id):
    blocked = require_perm("view_assets")
    if blocked: return blocked
    conn = db()
    asset = conn.execute("""SELECT a.*, c.name client_name
                            FROM assets a
                            JOIN clients c ON c.id=a.client_id
                            WHERE a.id=? AND a.marketplace_status='beschikbaar'""", (asset_id,)).fetchone()
    if not asset:
        conn.close()
        return redirect(url_for("marketplace", status=""))

    transport_option = request.form.get("transport_option") or "onderling_afstemmen"
    transport_labels = {
        "onderling_afstemmen": "Onderling afstemmen",
        "ophalen": "Ophalen",
        "office_interior": "Transportprijs aanvragen bij Follow O-I"
    }
    transport_label = transport_labels.get(transport_option, "Onderling afstemmen")

    conn.execute("""UPDATE assets
                    SET marketplace_status='gereserveerd', marketplace_reserved_by_user_id=?, marketplace_reserved_at=?
                    WHERE id=? AND marketplace_status='beschikbaar'""", (session.get("user_id"), now(), asset_id))

    price_request_sent = False
    if transport_option == "office_interior":
        price_request_sent = True
        request_client_id = request.form.get("request_client_id") or asset["client_id"]
        request_client = conn.execute("SELECT * FROM clients WHERE id=?", (request_client_id,)).fetchone()
        subject = f"Transportprijsaanvraag marketplace - {asset['asset_code']}"
        pickup = request.form.get("transport_from") or f"{asset['location'] or ''} {asset['room'] or ''}".strip()
        delivery = request.form.get("transport_to") or "Nog te bepalen"
        message = "\n".join([
            "Er is via de circulaire marketplace een transportprijsaanvraag verzonden naar Follow O-I.",
            "Dit is geen directe transportboeking. Graag de aanvraag beoordelen en de prijsopgave per e-mail beantwoorden aan de aanvrager.",
            "Transport wordt pas ingepland na akkoord op de offerte.",
            "",
            f"Asset: {asset['asset_code']} - {asset['category']}",
            f"Eigenaar / huidige organisatie: {asset['client_name']}",
            "",
            "Contact voor prijsopgave",
            f"Contactpersoon: {request.form.get('transport_contact_name') or '-'}",
            f"E-mail voor offerte: {request.form.get('transport_contact_email') or '-'}",
            f"Telefoon: {request.form.get('transport_contact_phone') or '-'}",
            "",
            "Ophaallocatie",
            f"Adres / locatie: {pickup}",
            f"Begane grond of verdieping: {request.form.get('pickup_floor_type') or '-'}",
            f"Verdieping: {request.form.get('pickup_floor_number') or '-'}",
            f"Lift aanwezig: {request.form.get('pickup_lift') or '-'}",
            f"Parkeren: {request.form.get('pickup_parking') or '-'}",
            f"Toelichting ophaallocatie: {request.form.get('pickup_note') or '-'}",
            "",
            "Loslocatie",
            f"Adres / locatie: {delivery}",
            f"Begane grond of verdieping: {request.form.get('delivery_floor_type') or '-'}",
            f"Verdieping: {request.form.get('delivery_floor_number') or '-'}",
            f"Lift aanwezig: {request.form.get('delivery_lift') or '-'}",
            f"Parkeren: {request.form.get('delivery_parking') or '-'}",
            f"Toelichting loslocatie: {request.form.get('delivery_note') or '-'}",
            "",
            f"Extra opmerkingen: {request.form.get('transport_note') or '-'}"
        ])
        conn.execute("""INSERT INTO tickets
                        (client_id,asset_id,created_by_user_id,contact_name,contact_email,contact_phone,subject,category,priority,location,room,message,assigned_to_name,assigned_to_email,status,created_at,updated_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (request_client_id, asset_id, session.get("user_id"),
                      request.form.get("transport_contact_name"), request.form.get("transport_contact_email"), request.form.get("transport_contact_phone"),
                      subject, "Marketplace vervoer", "Middel", pickup, delivery, message,
                      request_client["account_manager_name"] if request_client else None,
                      request_client["account_manager_email"] if request_client else None,
                      "nieuw", now(), now()))

    conn.commit(); conn.close()
    log_event(session.get("user_id"), "MARKETPLACE_RESERVE", f"Asset {asset_id} gereserveerd - vervoer: {transport_label}")
    if price_request_sent:
        return redirect(url_for("marketplace", status="", price_request="verzonden"))
    return redirect(url_for("marketplace", status=""))

@app.route("/marketplace/<int:asset_id>/release", methods=["POST"])
def marketplace_release(asset_id):
    blocked = require_perm("edit_assets")
    if blocked: return blocked
    conn = db()
    conn.execute("""UPDATE assets
                    SET marketplace_status='beschikbaar', marketplace_reserved_by_user_id=NULL, marketplace_reserved_at=NULL
                    WHERE id=?""", (asset_id,))
    conn.commit(); conn.close()
    log_event(session.get("user_id"), "MARKETPLACE_RELEASE", f"Asset {asset_id} vrijgegeven")
    return redirect(url_for("marketplace", status=""))

@app.route("/products")
def products():
    if not require_login(): return redirect(url_for("login"))
    q = request.args.get("q","").strip()
    category = request.args.get("category","").strip()
    conn = db()
    categories = [r["category"] for r in conn.execute("SELECT DISTINCT category FROM products WHERE active=1 AND category IS NOT NULL AND category!='' ORDER BY category").fetchall()]
    sql = "SELECT * FROM products WHERE active=1"
    params = []
    if q:
        sql += " AND (name LIKE ? OR description LIKE ? OR tags LIKE ? OR sku LIKE ?)"
        params += [f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"]
    if category:
        sql += " AND category=?"
        params.append(category)
    sql += " ORDER BY category, name"
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return render_template("products.html", products=rows, categories=categories, q=q, selected_category=category)

@app.route("/products/new", methods=["GET","POST"])
def product_new():
    if not require_login(): return redirect(url_for("login"))
    if request.method == "POST":
        conn = db()
        image_url = request.form.get("image_url")
        product_photo = request.files.get("product_photo")
        if product_photo and product_photo.filename:
            safe = secure_filename(product_photo.filename)
            stored = f"product_{int(datetime.now().timestamp())}_{safe}"
            product_photo.save(os.path.join(UPLOAD_FOLDER, stored))
            image_url = url_for("uploads", filename=stored)
        conn.execute("""INSERT INTO products
                        (sku,name,category,description,price_text,image_url,source_url,tags,active,created_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?)""",
                     (request.form.get("sku"), request.form["name"], request.form.get("category"),
                      request.form.get("description"), request.form.get("price_text"), image_url,
                      request.form.get("source_url"), request.form.get("tags"), 1, now()))
        conn.commit()
        conn.close()
        return redirect(url_for("products"))
    return render_template("product_form.html")

@app.route("/products/<int:product_id>/quote")
def product_quote(product_id):
    if not require_login(): return redirect(url_for("login"))
    return redirect(url_for("order_new", product_id=product_id))

@app.route("/orders")
def orders():
    blocked = require_perm("view_orders")
    if blocked: return blocked
    conn = db()
    rows = conn.execute("""SELECT o.*, c.name client_name FROM orders o JOIN clients c ON c.id=o.client_id
                           ORDER BY o.id DESC""").fetchall()
    conn.close()
    return render_template("orders.html", orders=rows)

@app.route("/orders/new", methods=["GET","POST"])
def order_new():
    blocked = require_perm("edit_orders")
    if blocked: return blocked
    conn = db()
    clients = conn.execute("SELECT id,name FROM clients ORDER BY name").fetchall()
    preselect = request.args.get("client_id")
    product_id = request.args.get("product_id")
    selected_product = None
    if product_id:
        selected_product = conn.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
    if request.method == "POST":
        conn.execute("""INSERT INTO orders
                        (client_id,furniture_type,quantity,color,quality,delivery_location,room,desired_delivery_date,assembly,note,status,created_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (request.form["client_id"], request.form["furniture_type"], request.form["quantity"], request.form.get("color"),
                      request.form.get("quality"), request.form.get("delivery_location"), request.form.get("room"),
                      request.form.get("desired_delivery_date"), request.form.get("assembly"), request.form.get("note"),
                      "offerte aangevraagd", now()))
        conn.commit()
        cid = request.form["client_id"]
        conn.close()
        return redirect(url_for("client_portal", client_id=cid))
    conn.close()
    return render_template("order_form.html", clients=clients, preselect=preselect, selected_product=selected_product)

@app.route("/damages", methods=["GET","POST"])
def damages():
    blocked = require_perm("view_damages")
    if blocked: return blocked
    conn = db()
    clients = conn.execute("SELECT id,name FROM clients ORDER BY name").fetchall()
    assets = conn.execute("SELECT id,asset_code,category FROM assets ORDER BY asset_code").fetchall()
    preselect = request.args.get("client_id")
    if request.method == "POST":
        edit_blocked = require_perm("edit_damages")
        if edit_blocked: return edit_blocked
        filename = None
        f = request.files.get("photo")
        if f and f.filename:
            safe = secure_filename(f.filename)
            filename = f"{int(datetime.now().timestamp())}_{safe}"
            f.save(os.path.join(UPLOAD_FOLDER, filename))
        conn.execute("""INSERT INTO damages
                        (client_id,asset_id,contact_name,contact_email,contact_phone,location,room,urgency,description,photo_path,status,created_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (request.form["client_id"], request.form.get("asset_id") or None, request.form.get("contact_name"),
                      request.form.get("contact_email"), request.form.get("contact_phone"), request.form.get("location"),
                      request.form.get("room"), request.form.get("urgency"), request.form["description"], filename, "nieuw", now()))
        conn.commit()
        conn.close()
        return redirect(url_for("damages"))
    rows = conn.execute("""SELECT d.*, c.name client_name, a.asset_code FROM damages d
                           JOIN clients c ON c.id=d.client_id
                           LEFT JOIN assets a ON a.id=d.asset_id
                           WHERE d.status!='opgelost'
                           ORDER BY d.id DESC""").fetchall()
    conn.close()
    return render_template("damages.html", damages=rows, clients=clients, assets=assets, preselect=preselect)

@app.route("/damages/new", methods=["GET","POST"])
def damage_new():
    return redirect(url_for("damages", client_id=request.args.get("client_id") or ""))



@app.route("/quick-ticket", methods=["GET","POST"])
def quick_ticket():
    if not require_login(): return redirect(url_for("login"))
    conn = db()
    clients = conn.execute("SELECT id,name,account_manager_name,account_manager_email FROM clients ORDER BY name").fetchall()
    preselect = request.args.get("client_id")
    if request.method == "POST":
        client = conn.execute("SELECT * FROM clients WHERE id=?", (request.form["client_id"],)).fetchone()
        conn.execute("""INSERT INTO tickets
                        (client_id,created_by_user_id,contact_name,contact_email,contact_phone,subject,category,priority,location,room,message,assigned_to_name,assigned_to_email,status,created_at,updated_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (request.form["client_id"], session.get("user_id"),
                      request.form.get("contact_name"), request.form.get("contact_email"), request.form.get("contact_phone"),
                      request.form["subject"], request.form.get("category"), request.form.get("priority"),
                      request.form.get("location"), request.form.get("room"), request.form["message"],
                      client["account_manager_name"], client["account_manager_email"], "nieuw", now(), now()))
        conn.commit()
        cid = request.form["client_id"]
        conn.close()
        return redirect(url_for("ticket_sent", client_id=cid))
    conn.close()
    return render_template("quick_ticket.html", clients=clients, preselect=preselect)

@app.route("/ticket-sent/<int:client_id>")
def ticket_sent(client_id):
    if not require_login(): return redirect(url_for("login"))
    return render_template("ticket_sent.html", client_id=client_id)

@app.route("/tickets")
def tickets():
    if not require_login(): return redirect(url_for("login"))
    conn = db()
    rows = conn.execute("""SELECT t.*, c.name client_name, a.asset_code FROM tickets t
                           JOIN clients c ON c.id=t.client_id
                           LEFT JOIN assets a ON a.id=t.asset_id
                           ORDER BY CASE t.priority WHEN 'Hoog' THEN 1 WHEN 'Middel' THEN 2 ELSE 3 END, t.id DESC""").fetchall()
    conn.close()
    return render_template("tickets.html", tickets=rows)

@app.route("/tickets/new", methods=["GET","POST"])
def ticket_new():
    if not require_login(): return redirect(url_for("login"))
    conn = db()
    clients = conn.execute("SELECT id,name,account_manager_name,account_manager_email,account_manager_phone FROM clients ORDER BY name").fetchall()
    assets = conn.execute("SELECT id,asset_code,category,location,room FROM assets ORDER BY asset_code").fetchall()
    preselect = request.args.get("client_id")
    if request.method == "POST":
        filename = None
        f = request.files.get("attachment")
        if f and f.filename:
            safe = secure_filename(f.filename)
            filename = f"{int(datetime.now().timestamp())}_{safe}"
            f.save(os.path.join(UPLOAD_FOLDER, filename))

        client = conn.execute("SELECT * FROM clients WHERE id=?", (request.form["client_id"],)).fetchone()
        conn.execute("""INSERT INTO tickets
                        (client_id,asset_id,created_by_user_id,contact_name,contact_email,contact_phone,subject,category,priority,location,room,message,attachment_path,assigned_to_name,assigned_to_email,status,created_at,updated_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (request.form["client_id"], request.form.get("asset_id") or None, session.get("user_id"),
                      request.form.get("contact_name"), request.form.get("contact_email"), request.form.get("contact_phone"),
                      request.form["subject"], request.form.get("category"), request.form.get("priority"),
                      request.form.get("location"), request.form.get("room"), request.form["message"],
                      filename, client["account_manager_name"], client["account_manager_email"], "nieuw", now(), now()))
        conn.commit()
        cid = request.form["client_id"]
        conn.close()
        return redirect(url_for("client_portal", client_id=cid))
    conn.close()
    return render_template("ticket_form.html", clients=clients, assets=assets, preselect=preselect)

@app.route("/tickets/<int:ticket_id>", methods=["GET","POST"])
def ticket_detail(ticket_id):
    if not require_login(): return redirect(url_for("login"))
    conn = db()
    ticket = conn.execute("""SELECT t.*, c.name client_name, c.account_manager_name, c.account_manager_email, c.account_manager_phone, a.asset_code
                             FROM tickets t
                             JOIN clients c ON c.id=t.client_id
                             LEFT JOIN assets a ON a.id=t.asset_id
                             WHERE t.id=?""", (ticket_id,)).fetchone()
    if not ticket:
        conn.close()
        return redirect(url_for("tickets"))

    if request.method == "POST":
        conn.execute("""UPDATE tickets
                        SET status=?, priority=?, last_response=?, updated_at=?
                        WHERE id=?""",
                     (request.form.get("status"), request.form.get("priority"), request.form.get("last_response"), now(), ticket_id))
        conn.commit()
        conn.close()
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    conn.close()
    return render_template("ticket_detail.html", ticket=ticket)

@app.route("/documents")
def documents():
    blocked = require_perm("view_documents")
    if blocked: return blocked
    conn = db()
    rows = conn.execute("""SELECT d.*, c.name client_name FROM documents d JOIN clients c ON c.id=d.client_id
                           ORDER BY d.id DESC""").fetchall()
    conn.close()
    return render_template("documents.html", documents=rows)

@app.route("/documents/new", methods=["GET","POST"])
def document_new():
    blocked = require_perm("upload_documents")
    if blocked: return blocked
    conn = db()
    clients = conn.execute("SELECT id,name FROM clients ORDER BY name").fetchall()
    preselect = request.args.get("client_id")
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            return "Geen bestand gekozen"
        safe = secure_filename(f.filename)
        stored = f"{int(datetime.now().timestamp())}_{safe}"
        f.save(os.path.join(UPLOAD_FOLDER, stored))
        conn.execute("""INSERT INTO documents (client_id,doc_type,filename,stored_filename,note,created_at)
                        VALUES (?,?,?,?,?,?)""",
                     (request.form["client_id"], request.form["doc_type"], safe, stored, request.form.get("note"), now()))
        conn.commit()
        cid = request.form["client_id"]
        conn.close()
        return redirect(url_for("client_portal", client_id=cid))
    conn.close()
    return render_template("document_form.html", clients=clients, preselect=preselect)

@app.route("/login-assets/<path:filename>")
def login_assets(filename):
    # Public assets for the login page only.
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=False)

@app.route("/uploads/<path:filename>")
def uploads(filename):
    if not require_login(): return redirect(url_for("login"))
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=False)

@app.route("/impact")
def impact():
    blocked = require_perm("view_impact")
    if blocked: return blocked
    conn = db()
    co2 = round(conn.execute("SELECT COALESCE(SUM(co2_kg),0) c FROM assets").fetchone()["c"])
    material = round(conn.execute("SELECT COALESCE(SUM(material_kg),0) c FROM assets").fetchone()["c"])
    cost = round(conn.execute("SELECT COALESCE(SUM(cost_saving_eur),0) c FROM assets").fetchone()["c"])
    total = conn.execute("SELECT COUNT(*) c FROM assets").fetchone()["c"]
    circular = conn.execute("SELECT COUNT(*) c FROM assets WHERE circular_source IN ('bestaand','second-life','refurbished')").fetchone()["c"]
    conn.close()
    data = {"co2":co2, "material":material, "cost":cost, "trees":round(co2/20), "car":round(co2/0.15) if co2 else 0, "circular":round((circular/max(total,1))*100)}
    return render_template("impact.html", data=data)

@app.route("/impact/report")
def impact_report():
    blocked = require_perm("view_impact")
    if blocked: return blocked
    conn = db()
    totals = {
        "assets": conn.execute("SELECT COUNT(*) c FROM assets").fetchone()["c"],
        "co2": round(conn.execute("SELECT COALESCE(SUM(co2_kg),0) c FROM assets").fetchone()["c"]),
        "material": round(conn.execute("SELECT COALESCE(SUM(material_kg),0) c FROM assets").fetchone()["c"]),
        "cost": round(conn.execute("SELECT COALESCE(SUM(cost_saving_eur),0) c FROM assets").fetchone()["c"]),
        "circular": conn.execute("SELECT COUNT(*) c FROM assets WHERE circular_source IN ('bestaand','second-life','refurbished','herplaatsing')").fetchone()["c"],
    }
    rows = conn.execute("""SELECT c.name client_name, COUNT(a.id) total_assets,
                            ROUND(COALESCE(SUM(a.co2_kg),0)) co2,
                            ROUND(COALESCE(SUM(a.material_kg),0)) material,
                            ROUND(COALESCE(SUM(a.cost_saving_eur),0)) cost
                            FROM assets a JOIN clients c ON c.id=a.client_id
                            GROUP BY c.name ORDER BY c.name""").fetchall()
    conn.close()
    circular_pct = round((totals["circular"] / max(totals["assets"], 1)) * 100)
    today_text = datetime.now().strftime("%d-%m-%Y")
    row_html = "".join([f"<tr><td>{html.escape(str(r['client_name']))}</td><td>{r['total_assets']}</td><td>{r['co2']} kg</td><td>{r['material']} kg</td><td>EUR {r['cost']}</td></tr>" for r in rows])
    report = f"""<!doctype html><html><head><meta charset='utf-8'><title>Impactrapport Follow O-I</title>
<style>body{{font-family:Arial,sans-serif;background:#f6f3ee;color:#172033;margin:0;padding:32px}}.wrap{{max-width:1000px;margin:auto;background:#fffdf8;border:1px solid #e6ded2;border-radius:20px;padding:32px}}.brand{{color:#0f3d3e;font-size:28px;font-weight:900}}.line{{height:5px;background:linear-gradient(90deg,#0f3d3e,#b88a44);border-radius:999px;margin:18px 0 26px}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:22px 0}}.card{{border:1px solid #e6ded2;border-radius:16px;padding:18px;background:#fdfaf4}}.kpi{{font-size:26px;font-weight:900;color:#0f3d3e}}.muted{{color:#6b7280}}table{{width:100%;border-collapse:collapse;margin-top:18px}}th,td{{padding:12px;border-bottom:1px solid #e6ded2;text-align:left}}th{{color:#6b7280;text-transform:uppercase;font-size:12px}}@media print{{body{{background:#fff;padding:0}}.wrap{{border:0}}}}</style></head>
<body><div class='wrap'><div class='brand'>Follow O-I Impactrapport</div><div class='muted'>Follow O-I | gegenereerd op {today_text}</div><div class='line'></div>
<h1>Circulaire impact en assetstatistieken</h1><p>Dit rapport geeft een overzicht van de geregistreerde impact binnen Follow O-I. De cijfers zijn gebaseerd op de actuele assetregistratie in het portaal.</p>
<div class='grid'><div class='card'><div class='muted'>Assets</div><div class='kpi'>{totals['assets']}</div></div><div class='card'><div class='muted'>CO2 vermeden</div><div class='kpi'>{totals['co2']} kg</div></div><div class='card'><div class='muted'>Materiaalbehoud</div><div class='kpi'>{totals['material']} kg</div></div><div class='card'><div class='muted'>Kostenbesparing</div><div class='kpi'>EUR {totals['cost']}</div></div></div>
<h2>Samenvatting</h2><p><strong>{circular_pct}%</strong> van het geregistreerde meubilair heeft een circulaire bron of herplaatsingsstatus. De indicatieve besparing komt uit op <strong>{totals['co2']} kg CO2</strong>, <strong>{totals['material']} kg materiaalbehoud</strong> en <strong>EUR {totals['cost']}</strong> kostenbesparing.</p>
<h2>Impact per klant</h2><table><tr><th>Klant</th><th>Assets</th><th>CO2</th><th>Materiaal</th><th>Kostenbesparing</th></tr>{row_html}</table>
<p class='muted'>Indicatieve rapportage. Werkelijke impact kan afhankelijk zijn van rekenmethodiek, toepassing en projectcontext.</p></div></body></html>"""
    filename = f"follow-oi-impactrapport-{datetime.now().strftime('%Y%m%d')}.html"
    return Response(report, mimetype="text/html", headers={"Content-Disposition": f"attachment; filename={filename}"})

@app.route("/rfid", methods=["GET","POST"])
def rfid():
    blocked = require_perm("view_rfid")
    if blocked: return blocked
    generated = []
    if request.method == "POST":
        client = request.form.get("client","KLANT")
        prefix = request.form.get("prefix","RFID-OI")
        qty = min(250, max(1, int(request.form.get("qty", 10))))
        start = int(request.form.get("start", 1))
        client_code = "".join([c for c in client.upper() if c.isalnum()])[:4] or "KLNT"
        for i in range(qty):
            generated.append(f"{prefix}-{client_code}-{str(start+i).zfill(6)}")
    return render_template("rfid.html", generated=generated)

@app.route("/rfid/download")
def rfid_download():
    if not require_login(): return redirect(url_for("login"))
    codes = request.args.get("codes","").split(",")
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["rfid","status"])
    for code in codes:
        if code:
            w.writerow([code,"vrij"])
    return Response(out.getvalue(), mimetype="text/csv", headers={"Content-Disposition":"attachment; filename=follow-oi-rfid.csv"})

@app.route("/emvi")
def emvi():
    blocked = require_perm("view_emvi")
    if blocked: return blocked
    conn = db()
    total = conn.execute("SELECT COUNT(*) c FROM assets").fetchone()["c"]
    co2 = round(conn.execute("SELECT COALESCE(SUM(co2_kg),0) c FROM assets").fetchone()["c"])
    material = round(conn.execute("SELECT COALESCE(SUM(material_kg),0) c FROM assets").fetchone()["c"])
    conn.close()
    text = f"""Follow O-I biedt klanten via Follow O-I een persoonlijk digitaal klantportaal. De klant ziet hierin het actuele meubelbestand, inclusief locatie, ruimte, aanschafdatum, conditie, servicehistorie en unieke RFID-code.

Daarnaast beschikt iedere klant over een vast aanspreekpunt met directe contactgegevens en een terugvalroute naar het algemene Follow O-I team. Nieuwe meubelaanvragen, schademeldingen en serviceverzoeken worden centraal vastgelegd, waardoor Follow O-I traceerbaar, proactief en datagedreven kan sturen op onderhoud, hergebruik en levensduurverlenging.

Binnen de huidige dataset zijn {total} assets geregistreerd met indicatief {co2} kg vermeden CO₂ en {material} kg materiaalbehoud."""
    return render_template("emvi.html", text=text)

@app.route("/users")
def users():
    blocked = require_perm("manage_users")
    if blocked: return blocked
    if current_user()["role"] != "admin": return redirect(url_for("dashboard"))
    conn = db()
    rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    conn.close()
    return render_template("users.html", users=rows)

@app.route("/users/new", methods=["GET","POST"])
def user_new():
    blocked = require_perm("manage_users")
    if blocked: return blocked
    if current_user()["role"] != "admin": return redirect(url_for("dashboard"))
    invite = ""
    if request.method == "POST":
        token = secrets.token_urlsafe(24)
        temp = secrets.token_urlsafe(12)
        conn = db()
        role = request.form["role"]
        selected_permissions = request.form.getlist("permissions") or ROLE_DEFAULTS.get(role, [])
        conn.execute("""INSERT INTO users (name,email,phone,role,password,active,email_verified,two_factor_enabled,invite_token,created_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?)""",
                     (request.form["name"], request.form["email"].strip().lower(), request.form.get("phone"), role, temp, 0, 0, 1, token, now()))
        user_id = conn.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        conn.commit(); conn.close()
        set_permissions(user_id, selected_permissions)
        invite = url_for("invite", token=token, _external=True)
    return render_template("user_form.html", invite=invite)

@app.route("/users/<int:user_id>/permissions", methods=["GET","POST"])
def user_permissions_edit(user_id):
    blocked = require_perm("manage_users")
    if blocked: return blocked
    conn = db(); edited = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not edited:
        conn.close(); return redirect(url_for("users"))
    if request.method == "POST":
        role = request.form.get("role", edited["role"])
        two_factor_enabled = 1 if request.form.get("two_factor_enabled") == "on" else 0
        permissions = request.form.getlist("permissions")
        conn.execute("UPDATE users SET role=?, two_factor_enabled=? WHERE id=?", (role, two_factor_enabled, user_id)); conn.commit(); conn.close()
        set_permissions(user_id, permissions)
        return redirect(url_for("users"))
    current_permissions = get_permissions(user_id); conn.close()
    return render_template("permissions.html", edited=edited, current_permissions=current_permissions, permission_keys=PERMISSION_KEYS)

@app.route("/invite/<token>", methods=["GET","POST"])
def invite(token):
    conn = db()
    invited = conn.execute("SELECT * FROM users WHERE invite_token=? AND active=0", (token,)).fetchone()
    if not invited:
        conn.close()
        return render_template("invite.html", invalid=True)
    error = ""
    if request.method == "POST":
        p1 = request.form.get("password","")
        p2 = request.form.get("password2","")
        if len(p1) < 8:
            error = "Gebruik minimaal 8 tekens."
        elif p1 != p2:
            error = "Wachtwoorden zijn niet gelijk."
        else:
            conn.execute("UPDATE users SET password=?, active=1, email_verified=1, two_factor_enabled=1, invite_token=NULL WHERE id=?", (p1, invited["id"]))
            conn.commit(); conn.close()
            return render_template("invite.html", success=True)
    conn.close()
    return render_template("invite.html", invite_user=invited, error=error)

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
