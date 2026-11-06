import os
import time
import secrets
import hashlib
import logging
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timezone

logger = logging.getLogger("celestia.auth")


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    Hash a password with PBKDF2-HMAC-SHA256 and a cryptographically secure salt.
    Returns (hex_hash, salt).
    """
    if salt is None:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return key.hex(), salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verify an input password against stored PBKDF2 hash and salt."""
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return secrets.compare_digest(key.hex(), stored_hash)


class AuthManager:
    """
    User Authentication and Active Session Presence Subsystem.
    Maintains persistent user accounts, active presence heartbeats, and determines
    whether critical voice phone calls should be suppressed when an operator is actively on site.
    """

    def __init__(self, db_manager=None):
        self._db = db_manager
        self.presence_timeout_seconds = 45  # Inactive if no heartbeat within 45s
        self._last_web_heartbeat_epoch = 0.0
        self._init_tables()
        self._seed_default_admin()

    @property
    def db(self):
        if self._db is None:
            from app.storage.database import DatabaseManager
            self._db = DatabaseManager()
        return self._db

    def _init_tables(self):
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                is_pg = (self.db.db_type == "postgres")
                if is_pg:
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS users (
                            id SERIAL PRIMARY KEY,
                            username TEXT UNIQUE NOT NULL,
                            email TEXT UNIQUE NOT NULL,
                            password_hash TEXT NOT NULL,
                            salt TEXT NOT NULL,
                            full_name TEXT,
                            role TEXT DEFAULT 'admin',
                            created_at TEXT NOT NULL
                        );
                        CREATE TABLE IF NOT EXISTS user_sessions (
                            session_token TEXT PRIMARY KEY,
                            user_id INTEGER NOT NULL,
                            username TEXT NOT NULL,
                            created_at TEXT NOT NULL,
                            last_heartbeat TEXT NOT NULL,
                            last_heartbeat_epoch REAL NOT NULL,
                            ip_address TEXT,
                            user_agent TEXT,
                            status TEXT DEFAULT 'active',
                            is_active INTEGER DEFAULT 1
                        );
                    """)
                else:
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            email TEXT UNIQUE NOT NULL,
                            password_hash TEXT NOT NULL,
                            salt TEXT NOT NULL,
                            full_name TEXT,
                            role TEXT DEFAULT 'admin',
                            created_at TEXT NOT NULL
                        )
                    """)
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS user_sessions (
                            session_token TEXT PRIMARY KEY,
                            user_id INTEGER NOT NULL,
                            username TEXT NOT NULL,
                            created_at TEXT NOT NULL,
                            last_heartbeat TEXT NOT NULL,
                            last_heartbeat_epoch REAL NOT NULL,
                            ip_address TEXT,
                            user_agent TEXT,
                            status TEXT DEFAULT 'active',
                            is_active INTEGER DEFAULT 1
                        )
                    """)
        except Exception as e:
            logger.error(f"Failed to initialize auth tables: {e}")

    def _seed_default_admin(self):
        """Seed a standard security admin if no users exist yet."""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as cnt FROM users")
                row = cursor.fetchone()
                cnt = row["cnt"] if isinstance(row, dict) else row[0]
                if cnt == 0:
                    pw_hash, salt = hash_password("admin123")
                    now_str = datetime.now(timezone.utc).isoformat()
                    is_pg = (self.db.db_type == "postgres")
                    if is_pg:
                        cursor.execute(
                            "INSERT INTO users (username, email, password_hash, salt, full_name, role, created_at) "
                            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                            ("admin", "admin@celestia.local", pw_hash, salt, "SOC Lead Operator", "admin", now_str)
                        )
                    else:
                        cursor.execute(
                            "INSERT INTO users (username, email, password_hash, salt, full_name, role, created_at) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?)",
                            ("admin", "admin@celestia.local", pw_hash, salt, "SOC Lead Operator", "admin", now_str)
                        )
                    logger.info("Seeded initial default SOC admin user 'admin'")
        except Exception as e:
            logger.debug(f"Default admin check/seed: {e}")

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        full_name: Optional[str] = None,
        role: str = "operator",
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Register a new user account and log them in immediately with a new session."""
        username = username.strip().lower()
        email = email.strip().lower()
        if not username or len(username) < 3:
            raise ValueError("Username must be at least 3 characters long.")
        if not email or "@" not in email:
            raise ValueError("Valid email address is required.")
        if not password or len(password) < 6:
            raise ValueError("Password must be at least 6 characters long.")

        # Check existing
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            is_pg = (self.db.db_type == "postgres")
            if is_pg:
                cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
            else:
                cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
            if cursor.fetchone():
                raise ValueError("A user with this username or email already exists.")

            pw_hash, salt = hash_password(password)
            now = datetime.now(timezone.utc)
            now_str = now.isoformat()
            full_name = full_name or username.capitalize()

            if is_pg:
                cursor.execute(
                    "INSERT INTO users (username, email, password_hash, salt, full_name, role, created_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
                    (username, email, pw_hash, salt, full_name, role, now_str)
                )
                user_id = cursor.fetchone()["id"]
            else:
                cursor.execute(
                    "INSERT INTO users (username, email, password_hash, salt, full_name, role, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (username, email, pw_hash, salt, full_name, role, now_str)
                )
                user_id = cursor.lastrowid

        # Automatically create active session
        session = self._create_session(
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        return {
            "status": "success",
            "message": "User registered successfully.",
            "token": session["token"],
            "user": {
                "id": user_id,
                "username": username,
                "email": email,
                "full_name": full_name,
                "role": role,
            },
        }

    def authenticate_user(
        self,
        username_or_email: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Authenticate user with username/email and password."""
        ident = username_or_email.strip().lower()
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            is_pg = (self.db.db_type == "postgres")
            if is_pg:
                cursor.execute(
                    "SELECT id, username, email, password_hash, salt, full_name, role FROM users "
                    "WHERE username = %s OR email = %s",
                    (ident, ident)
                )
            else:
                cursor.execute(
                    "SELECT id, username, email, password_hash, salt, full_name, role FROM users "
                    "WHERE username = ? OR email = ?",
                    (ident, ident)
                )
            user_row = cursor.fetchone()

        if not user_row:
            raise ValueError("Invalid username or password.")

        if isinstance(user_row, dict):
            uid = user_row["id"]
            uname = user_row["username"]
            email = user_row["email"]
            phash = user_row["password_hash"]
            salt = user_row["salt"]
            fname = user_row["full_name"]
            role = user_row["role"]
        else:
            uid, uname, email, phash, salt, fname, role = user_row

        if not verify_password(password, phash, salt):
            raise ValueError("Invalid username or password.")

        session = self._create_session(
            user_id=uid,
            username=uname,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        return {
            "status": "success",
            "message": "Authentication successful.",
            "token": session["token"],
            "user": {
                "id": uid,
                "username": uname,
                "email": email,
                "full_name": fname or uname,
                "role": role,
            },
        }

    def _create_session(
        self,
        user_id: int,
        username: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        token = secrets.token_hex(32)
        now = time.time()
        now_str = datetime.now(timezone.utc).isoformat()
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            is_pg = (self.db.db_type == "postgres")
            if is_pg:
                cursor.execute(
                    "INSERT INTO user_sessions (session_token, user_id, username, created_at, last_heartbeat, last_heartbeat_epoch, ip_address, user_agent, status, is_active) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 1)",
                    (token, user_id, username, now_str, now_str, now, ip_address, user_agent, "active")
                )
            else:
                cursor.execute(
                    "INSERT INTO user_sessions (session_token, user_id, username, created_at, last_heartbeat, last_heartbeat_epoch, ip_address, user_agent, status, is_active) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
                    (token, user_id, username, now_str, now_str, now, ip_address, user_agent, "active")
                )
        return {"token": token, "username": username}

    def logout_session(self, session_token: str) -> bool:
        """Close an active user session."""
        if not session_token:
            return False
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            is_pg = (self.db.db_type == "postgres")
            if is_pg:
                cursor.execute(
                    "UPDATE user_sessions SET status = 'logged_out', is_active = 0 WHERE session_token = %s",
                    (session_token,)
                )
            else:
                cursor.execute(
                    "UPDATE user_sessions SET status = 'logged_out', is_active = 0 WHERE session_token = ?",
                    (session_token,)
                )
        return True

    def record_heartbeat(
        self,
        session_token: str,
        is_visible: bool = True,
        ip_address: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Record a periodic browser presence heartbeat from a client on the web console.
        Updates session epoch and marks operator as actively viewing the console.
        """
        now = time.time()
        now_str = datetime.now(timezone.utc).isoformat()
        status_val = "active" if is_visible else "away"

        if is_visible:
            self._last_web_heartbeat_epoch = now

        # Allow guest or anonymous web console presence tracking
        if not session_token or session_token in ("guest", "guest_web_session", "none", "null"):
            return {
                "active": True,
                "username": "Web Console User",
                "status": status_val,
                "timestamp": now_str,
            }

        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            is_pg = (self.db.db_type == "postgres")
            if is_pg:
                cursor.execute(
                    "UPDATE user_sessions SET last_heartbeat = %s, last_heartbeat_epoch = %s, status = %s, is_active = 1 "
                    "WHERE session_token = %s RETURNING username, user_id",
                    (now_str, now, status_val, session_token)
                )
                row = cursor.fetchone()
            else:
                cursor.execute(
                    "UPDATE user_sessions SET last_heartbeat = ?, last_heartbeat_epoch = ?, status = ?, is_active = 1 "
                    "WHERE session_token = ?",
                    (now_str, now, status_val, session_token)
                )
                cursor.execute("SELECT username, user_id FROM user_sessions WHERE session_token = ?", (session_token,))
                row = cursor.fetchone()

        if not row:
            return {"active": False, "error": "Invalid or expired session"}

        uname = row["username"] if isinstance(row, dict) else row[0]
        return {
            "active": True,
            "username": uname,
            "status": status_val,
            "timestamp": now_str,
        }

    def get_user_from_token(self, session_token: str) -> Optional[Dict[str, Any]]:
        """Retrieve user details for a given session token."""
        if not session_token:
            return None
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            is_pg = (self.db.db_type == "postgres")
            sql = (
                "SELECT u.id, u.username, u.email, u.full_name, u.role, s.status, s.last_heartbeat_epoch "
                "FROM user_sessions s JOIN users u ON s.user_id = u.id "
                "WHERE s.session_token = " + ("%s" if is_pg else "?") + " AND s.is_active = 1"
            )
            cursor.execute(sql, (session_token,))
            row = cursor.fetchone()
            if not row:
                return None
            if isinstance(row, dict):
                return row
            return {
                "id": row[0],
                "username": row[1],
                "email": row[2],
                "full_name": row[3],
                "role": row[4],
                "session_status": row[5],
                "last_heartbeat_epoch": row[6],
            }

    def check_presence(self, max_idle_seconds: Optional[int] = None) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Check if any operator is currently logged in and actively monitoring the web console.
        Returns (is_active_on_site, active_session_metadata).
        """
        window = max_idle_seconds or self.presence_timeout_seconds
        now = time.time()
        threshold_epoch = now - window

        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            is_pg = (self.db.db_type == "postgres")
            if is_pg:
                cursor.execute(
                    "SELECT session_token, username, user_id, status, last_heartbeat_epoch, ip_address "
                    "FROM user_sessions "
                    "WHERE is_active = 1 AND status = 'active' AND last_heartbeat_epoch >= %s "
                    "ORDER BY last_heartbeat_epoch DESC LIMIT 1",
                    (threshold_epoch,)
                )
            else:
                cursor.execute(
                    "SELECT session_token, username, user_id, status, last_heartbeat_epoch, ip_address "
                    "FROM user_sessions "
                    "WHERE is_active = 1 AND status = 'active' AND last_heartbeat_epoch >= ? "
                    "ORDER BY last_heartbeat_epoch DESC LIMIT 1",
                    (threshold_epoch,)
                )
            row = cursor.fetchone()

        if row:
            if isinstance(row, dict):
                uname = row["username"]
                ep = row["last_heartbeat_epoch"]
                ip = row.get("ip_address")
            else:
                uname = row[1]
                ep = row[4]
                ip = row[5]

            idle_s = int(now - ep)
            return True, {
                "username": uname,
                "idle_seconds": idle_s,
                "ip_address": ip,
                "active_window": window,
                "type": "authenticated_operator",
            }

        # 2. Check general web console presence (guest or active browser viewing site)
        last_web = getattr(self, "_last_web_heartbeat_epoch", 0.0)
        if (now - last_web) <= window:
            idle_s = int(now - last_web)
            return True, {
                "username": "Web Console User",
                "idle_seconds": idle_s,
                "ip_address": "browser",
                "active_window": window,
                "type": "web_presence",
            }

        return False, None

    def get_presence_status(self) -> Dict[str, Any]:
        """Return diagnostic presence status summary."""
        is_active, active_info = self.check_presence()
        now = time.time()
        active_sessions = []
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            is_pg = (self.db.db_type == "postgres")
            sql = (
                "SELECT session_token, username, status, last_heartbeat_epoch, ip_address "
                "FROM user_sessions WHERE is_active = 1 AND last_heartbeat_epoch >= "
                + ("%s" if is_pg else "?") + " ORDER BY last_heartbeat_epoch DESC"
            )
            cursor.execute(sql, (now - 300,))  # within last 5 minutes
            rows = cursor.fetchall()
            for r in rows:
                if isinstance(r, dict):
                    tok = r["session_token"]
                    un = r["username"]
                    st = r["status"]
                    lh = r["last_heartbeat_epoch"]
                    ip = r.get("ip_address")
                else:
                    tok, un, st, lh, ip = r[0], r[1], r[2], r[3], r[4]
                active_sessions.append({
                    "username": un,
                    "status": st,
                    "idle_seconds": int(now - lh),
                    "ip_address": ip,
                })

        return {
            "operator_present": is_active,
            "active_operator": active_info["username"] if active_info else None,
            "idle_seconds": active_info["idle_seconds"] if active_info else None,
            "voice_calls_suppressed": is_active,
            "presence_threshold_seconds": self.presence_timeout_seconds,
            "active_session_count": len([s for s in active_sessions if s["idle_seconds"] <= self.presence_timeout_seconds]),
            "sessions": active_sessions[:10],
        }


auth_manager = AuthManager()
