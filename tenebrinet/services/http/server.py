# tenebrinet/services/http/server.py
"""
HTTP Honeypot Server implementation.

Provides a fake web server that simulates a vulnerable CMS (WordPress)
to capture web-based attacks and attacker reconnaissance.
"""
import re
from typing import Optional

from aiohttp import web
import structlog

from tenebrinet.core.config import HTTPServiceConfig
from tenebrinet.core.database import AsyncSessionLocal
from tenebrinet.core.models import Attack, Credential


logger = structlog.get_logger()


# Common attack patterns to detect
ATTACK_PATTERNS = {
    "sql_injection": [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"union.*select",
        r"select.*from",
        r"insert.*into",
        r"drop.*table",
        r"update.*set",
        r"delete.*from",
    ],
    "xss": [
        r"<script[^>]*>",
        r"javascript:",
        r"on\w+\s*=",
        r"<img[^>]+onerror",
        r"<svg[^>]+onload",
    ],
    "path_traversal": [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e/",
        r"\.\.%2f",
        r"/etc/passwd",
        r"/etc/shadow",
        r"c:\\windows",
    ],
    "command_injection": [
        r";\s*\w+",
        r"\|\s*\w+",
        r"`[^`]+`",
        r"\$\([^)]+\)",
        r"&&\s*\w+",
    ],
    "lfi_rfi": [
        r"(file|php|zip|data|expect|input|phar)://",
        r"\.php\?",
        r"include\s*\(",
        r"require\s*\(",
    ],
}

# Suspicious paths that attackers commonly probe
SUSPICIOUS_PATHS = [
    "/wp-admin",
    "/wp-login.php",
    "/administrator",
    "/admin",
    "/phpmyadmin",
    "/mysql",
    "/.git",
    "/.env",
    "/config",
    "/backup",
    "/.htaccess",
    "/wp-config.php",
    "/xmlrpc.php",
    "/shell",
    "/cmd",
    "/eval",
    "/api/v1",
    "/graphql",
    "/.well-known",
    "/robots.txt",
    "/sitemap.xml",
]


class HTTPHoneypot:
    """
    HTTP Honeypot service that simulates a vulnerable web server.

    Captures and logs web-based attacks including form submissions,
    SQL injection attempts, and reconnaissance activity.
    """

    def __init__(self, config: HTTPServiceConfig) -> None:
        self.config = config
        self.host = config.host
        self.port = config.port
        self.fake_cms = config.fake_cms
        self.app: Optional[web.Application] = None
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        self._running = False

    async def start(self) -> None:
        """Start the HTTP honeypot server."""
        if self._running:
            logger.warning("http_honeypot_already_running")
            return

        logger.info(
            "http_honeypot_starting",
            host=self.host,
            port=self.port,
            fake_cms=self.fake_cms,
        )

        try:
            self.app = web.Application(
                middlewares=[self._request_logger_middleware]
            )
            self._setup_routes()

            self.runner = web.AppRunner(self.app)
            await self.runner.setup()

            self.site = web.TCPSite(self.runner, self.host, self.port)
            await self.site.start()

            self._running = True
            logger.info(
                "http_honeypot_started",
                host=self.host,
                port=self.port,
            )
        except Exception as e:
            logger.error(
                "http_honeypot_start_failed",
                error=str(e),
                exc_info=True,
            )
            raise

    async def stop(self) -> None:
        """Stop the HTTP honeypot server."""
        if not self._running:
            logger.warning("http_honeypot_not_running")
            return

        logger.info("http_honeypot_stopping")

        if self.runner:
            await self.runner.cleanup()

        self._running = False
        logger.info("http_honeypot_stopped")

    def _setup_routes(self) -> None:
        """Set up the routes for the fake web server."""
        if not self.app:
            return

        # Main pages
        self.app.router.add_get("/", self._handle_home)
        self.app.router.add_get("/index.php", self._handle_home)
        self.app.router.add_get("/index.html", self._handle_home)

        # WordPress simulation
        self.app.router.add_get("/wp-login.php", self._handle_wp_login)
        self.app.router.add_post("/wp-login.php", self._handle_wp_login_post)
        self.app.router.add_get("/wp-admin", self._handle_wp_admin)
        self.app.router.add_get("/wp-admin/", self._handle_wp_admin)
        self.app.router.add_post("/xmlrpc.php", self._handle_xmlrpc)

        # Common paths
        self.app.router.add_get("/robots.txt", self._handle_robots)
        self.app.router.add_get("/.env", self._handle_env_probe)
        self.app.router.add_get("/config.php", self._handle_config_probe)

        # Catch-all for any other path
        self.app.router.add_route("*", "/{path:.*}", self._handle_catchall)

    @web.middleware
    async def _request_logger_middleware(self, request, handler):
        """Middleware to log all requests."""
        client_ip = self._get_client_ip(request)

        # Capture request body for POST requests
        body = None
        if request.method == "POST":
            try:
                body = await request.text()
            except Exception:
                body = None

        # Detect attack patterns
        threat_type = await self._detect_threat(request, body)

        # Log the request
        logger.info(
            "http_request_received",
            client_ip=client_ip,
            method=request.method,
            path=request.path,
            query=str(request.query_string),
            user_agent=request.headers.get("User-Agent", ""),
            threat_type=threat_type,
        )

        # Record to database
        await self._record_attack(
            client_ip=client_ip,
            request=request,
            body=body,
            threat_type=threat_type,
        )

        try:
            response = await handler(request)
            return response
        except web.HTTPException:
            raise
        except Exception as e:
            logger.error("http_handler_error", error=str(e))
            return web.Response(
                text="Internal Server Error",
                status=500,
            )

    def _get_client_ip(self, request: web.Request) -> str:
        """Extract the client IP from the request."""
        # Check for proxy headers
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        peername = request.transport.get_extra_info("peername")
        if peername:
            return peername[0]

        return "unknown"

    async def _detect_threat(
        self, request: web.Request, body: Optional[str]
    ) -> str:
        """Detect the type of attack based on request patterns."""
        path = request.path.lower()
        query = str(request.query_string).lower()
        combined = f"{path}?{query}"

        if body:
            combined += f" {body.lower()}"

        # Check for attack patterns
        for threat_type, patterns in ATTACK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    return threat_type

        # Check for suspicious path probing
        for suspicious_path in SUSPICIOUS_PATHS:
            if path.startswith(suspicious_path.lower()):
                return "reconnaissance"

        # Check for common scanners
        user_agent = request.headers.get("User-Agent", "").lower()
        scanner_signatures = [
            "nikto", "sqlmap", "nmap", "masscan", "zgrab",
            "gobuster", "dirbuster", "wfuzz", "burp", "acunetix",
            "nessus", "qualys", "openvas", "w3af", "skipfish",
        ]
        for scanner in scanner_signatures:
            if scanner in user_agent:
                return "scanner"

        return "probe"

    async def _record_attack(
        self,
        client_ip: str,
        request: web.Request,
        body: Optional[str],
        threat_type: str,
    ) -> None:
        """Record the attack attempt in the database."""
        try:
            async with AsyncSessionLocal() as session:
                attack = Attack(
                    ip=client_ip,
                    service="http",
                    threat_type=threat_type,
                    payload={
                        "method": request.method,
                        "path": request.path,
                        "query": str(request.query_string),
                        "headers": dict(request.headers),
                        "body": body[:1000] if body else None,
                        "user_agent": request.headers.get("User-Agent", ""),
                    },
                )
                session.add(attack)
                await session.commit()

                logger.debug(
                    "http_attack_recorded",
                    attack_id=str(attack.id),
                    client_ip=client_ip,
                    threat_type=threat_type,
                )
        except Exception as e:
            logger.error("http_attack_record_failed", error=str(e))

    async def _record_credential(
        self, client_ip: str, username: str, password: str
    ) -> None:
        """Record captured credentials."""
        try:
            async with AsyncSessionLocal() as session:
                attack = Attack(
                    ip=client_ip,
                    service="http",
                    threat_type="credential_attack",
                    payload={
                        "type": "login_attempt",
                        "username": username,
                    },
                )
                session.add(attack)
                await session.flush()

                credential = Credential(
                    attack_id=attack.id,
                    username=username,
                    password=password,
                    success=False,
                )
                session.add(credential)
                await session.commit()

                logger.warning(
                    "http_credential_captured",
                    client_ip=client_ip,
                    username=username,
                )
        except Exception as e:
            logger.error("http_credential_record_failed", error=str(e))

    # --- Route Handlers ---

    async def _handle_home(self, request: web.Request) -> web.Response:
        """Handle the home page."""
        html = self._generate_wordpress_home()
        return web.Response(
            text=html,
            content_type="text/html",
            headers=self._get_wordpress_headers(),
        )

    async def _handle_wp_login(self, request: web.Request) -> web.Response:
        """Handle WordPress login page (GET)."""
        html = self._generate_wp_login_page()
        return web.Response(
            text=html,
            content_type="text/html",
            headers=self._get_wordpress_headers(),
        )

    async def _handle_wp_login_post(
        self, request: web.Request
    ) -> web.Response:
        """Handle WordPress login submission (POST)."""
        client_ip = self._get_client_ip(request)

        try:
            data = await request.post()
            username = data.get("log", "")
            password = data.get("pwd", "")

            if username or password:
                await self._record_credential(client_ip, username, password)

        except Exception as e:
            logger.error("http_login_parse_error", error=str(e))

        # Always return login failed
        html = self._generate_wp_login_page(error=True)
        return web.Response(
            text=html,
            content_type="text/html",
            headers=self._get_wordpress_headers(),
        )

    async def _handle_wp_admin(self, request: web.Request) -> web.Response:
        """Handle admin panel access - redirect to login."""
        raise web.HTTPFound("/wp-login.php?redirect_to=/wp-admin/")

    async def _handle_xmlrpc(self, request: web.Request) -> web.Response:
        """Handle XML-RPC requests (common attack vector)."""
        xml_response = """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>403</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>Forbidden</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>"""
        return web.Response(
            text=xml_response,
            content_type="text/xml",
            headers=self._get_wordpress_headers(),
        )

    async def _handle_robots(self, request: web.Request) -> web.Response:
        """Handle robots.txt - reveal some 'hidden' paths."""
        robots = """User-agent: *
Disallow: /wp-admin/
Disallow: /wp-includes/
Disallow: /backup/
Disallow: /private/
Disallow: /config/
Disallow: /.git/

Sitemap: http://example.com/sitemap.xml
"""
        return web.Response(text=robots, content_type="text/plain")

    async def _handle_env_probe(self, request: web.Request) -> web.Response:
        """Handle .env file probes - return fake credentials."""
        fake_env = """APP_NAME=WordPress
APP_ENV=production
APP_DEBUG=false

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=wordpress_prod
DB_USERNAME=wp_admin
DB_PASSWORD=W0rdPr3ss_S3cr3t_2024!

MAIL_HOST=smtp.mailtrap.io
MAIL_USERNAME=admin@example.com
MAIL_PASSWORD=mailP@ss123

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""
        logger.warning(
            "http_sensitive_file_accessed",
            path="/.env",
            client_ip=self._get_client_ip(request),
        )
        return web.Response(text=fake_env, content_type="text/plain")

    async def _handle_config_probe(
        self, request: web.Request
    ) -> web.Response:
        """Handle config file probes."""
        fake_config = """<?php
define('DB_NAME', 'wordpress_prod');
define('DB_USER', 'wp_admin');
define('DB_PASSWORD', 'W0rdPr3ss_S3cr3t_2024!');
define('DB_HOST', 'localhost');
define('AUTH_KEY', 'fake_auth_key_here');
?>"""
        logger.warning(
            "http_sensitive_file_accessed",
            path="/config.php",
            client_ip=self._get_client_ip(request),
        )
        return web.Response(text=fake_config, content_type="text/plain")

    async def _handle_catchall(self, request: web.Request) -> web.Response:
        """Handle any unmatched paths."""
        path = request.match_info.get("path", "")

        # Return 404 for most paths
        html = self._generate_404_page(path)
        return web.Response(
            text=html,
            status=404,
            content_type="text/html",
            headers=self._get_wordpress_headers(),
        )

    def _get_wordpress_headers(self) -> dict:
        """Return headers that simulate WordPress."""
        return {
            "Server": "Apache/2.4.41 (Ubuntu)",
            "X-Powered-By": "PHP/7.4.3",
            "X-Pingback": "/xmlrpc.php",
            "Link": '</>; rel="https://api.w.org/"',
        }

    def _generate_wordpress_home(self) -> str:
        """Generate a fake WordPress home page."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="generator" content="{self.fake_cms}">
    <title>Welcome | Company Blog</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif;
               max-width: 800px; margin: 50px auto; padding: 20px;
               color: #333; line-height: 1.6; }}
        header {{ border-bottom: 1px solid #ddd; padding-bottom: 20px;
                  margin-bottom: 30px; }}
        h1 {{ color: #0073aa; }}
        article {{ margin-bottom: 40px; padding-bottom: 20px;
                   border-bottom: 1px solid #eee; }}
        .meta {{ color: #666; font-size: 0.9em; }}
        footer {{ margin-top: 40px; color: #666; font-size: 0.85em; }}
        a {{ color: #0073aa; }}
    </style>
</head>
<body>
    <header>
        <h1>Company Blog</h1>
        <nav><a href="/">Home</a> | <a href="/about">About</a> |
             <a href="/contact">Contact</a></nav>
    </header>

    <main>
        <article>
            <h2>Welcome to Our New Website!</h2>
            <p class="meta">Posted on December 5, 2024 by Admin</p>
            <p>We are excited to launch our new company website.
               Stay tuned for more updates!</p>
            <p><a href="/2024/12/welcome-post/">Read more →</a></p>
        </article>

        <article>
            <h2>Q4 2024 Updates</h2>
            <p class="meta">Posted on November 28, 2024 by Admin</p>
            <p>Check out our latest quarterly updates...</p>
            <p><a href="/2024/11/q4-updates/">Read more →</a></p>
        </article>
    </main>

    <footer>
        <p>&copy; 2024 Company Name. Powered by {self.fake_cms}</p>
        <p><a href="/wp-admin/">Admin Login</a></p>
    </footer>
</body>
</html>"""

    def _generate_wp_login_page(self, error: bool = False) -> str:
        """Generate a fake WordPress login page."""
        error_html = ""
        if error:
            error_html = """
            <div id="login_error">
                <strong>Error:</strong> The username or password
                you entered is incorrect.
                <a href="/wp-login.php?action=lostpassword">
                Lost your password?</a>
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex,nofollow">
    <title>Log In &lsaquo; Company Blog &#8212; WordPress</title>
    <style>
        body {{ background: #f1f1f1; font-family: sans-serif;
               min-height: 100vh; display: flex; align-items: center;
               justify-content: center; margin: 0; }}
        #login {{ width: 320px; padding: 8% 0 0; }}
        h1 a {{ background-image: url('data:image/svg+xml,...');
                width: 84px; height: 84px; display: block; margin: 0 auto;
                text-indent: -9999px; }}
        .login form {{ margin-top: 20px; background: #fff;
                       padding: 26px 24px;
                       box-shadow: 0 1px 3px rgba(0,0,0,.13);
                       border-radius: 4px; }}
        .login label {{ font-size: 14px; color: #444; }}
        .login input[type=text], .login input[type=password] {{
            width: 100%; padding: 8px; margin: 2px 6px 16px 0;
            border: 1px solid #ddd; border-radius: 4px;
            box-sizing: border-box; font-size: 14px; }}
        .login input[type=submit] {{
            background: #0073aa; border: none; color: #fff;
            padding: 10px 20px; border-radius: 4px; cursor: pointer;
            font-size: 14px; width: 100%; }}
        .login input[type=submit]:hover {{ background: #006799; }}
        #login_error {{ background: #dc3232; color: #fff; padding: 12px;
                        margin-bottom: 16px; border-radius: 4px; }}
        #login_error a {{ color: #fff; }}
        .forgetmenot {{ margin-bottom: 16px; }}
        #nav, #backtoblog {{ text-align: center; margin-top: 16px; }}
        #nav a, #backtoblog a {{ color: #555; text-decoration: none; }}
    </style>
</head>
<body class="login">
    <div id="login">
        <h1><a href="https://wordpress.org/">WordPress</a></h1>
        {error_html}
        <form name="loginform" id="loginform" action="/wp-login.php"
              method="post">
            <p>
                <label for="user_login">Username or Email Address</label>
                <input type="text" name="log" id="user_login" size="20"
                       autocapitalize="off" autocomplete="username">
            </p>
            <p>
                <label for="user_pass">Password</label>
                <input type="password" name="pwd" id="user_pass" size="20"
                       autocomplete="current-password">
            </p>
            <p class="forgetmenot">
                <input name="rememberme" type="checkbox" id="rememberme"
                       value="forever">
                <label for="rememberme">Remember Me</label>
            </p>
            <p class="submit">
                <input type="submit" name="wp-submit" id="wp-submit"
                       class="button button-primary button-large"
                       value="Log In">
            </p>
        </form>
        <p id="nav">
            <a href="/wp-login.php?action=lostpassword">
            Lost your password?</a>
        </p>
        <p id="backtoblog">
            <a href="/">&larr; Go to Company Blog</a>
        </p>
    </div>
</body>
</html>"""

    def _generate_404_page(self, path: str) -> str:
        """Generate a 404 error page."""
        # path parameter available for future customization
        _ = path  # suppress unused variable warning
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Page not found | Company Blog</title>
    <style>
        body {{ font-family: sans-serif; text-align: center;
               padding: 50px; color: #444; }}
        h1 {{ font-size: 48px; color: #0073aa; }}
        p {{ font-size: 18px; }}
        a {{ color: #0073aa; }}
    </style>
</head>
<body>
    <h1>404</h1>
    <p>Oops! That page can't be found.</p>
    <p><a href="/">Return to homepage</a></p>
</body>
</html>"""

    async def health_check(self) -> dict:
        """Check if the HTTP honeypot is healthy."""
        return {
            "service": "http_honeypot",
            "running": self._running,
            "host": self.host,
            "port": self.port,
            "fake_cms": self.fake_cms,
        }
