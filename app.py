from flask import Flask, render_template, request
import requests
import validators
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

app = Flask(__name__)


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():
    return render_template("index.html")


# =========================================================
# START SCAN
# =========================================================

@app.route("/start-scan", methods=["POST"])
def start_scan():

    url = request.form.get("url", "").strip()

    # URL empty
    if not url:
        return """
        <h1>URL Missing</h1>
        <p>Please enter a website URL.</p>
        <a href="/">Go Back</a>
        """

    # URL validation
    if not validators.url(url):
        return """
        <h1>Invalid URL</h1>
        <p>Please enter a valid URL.</p>
        <p>Example: https://example.com</p>
        <a href="/">Try Again</a>
        """

    # Protocol validation
    parsed_url = urlparse(url)

    if parsed_url.scheme not in ["http", "https"]:
        return """
        <h1>Unsupported URL</h1>
        <p>Only HTTP and HTTPS websites are allowed.</p>
        <a href="/">Try Again</a>
        """

    return render_template(
        "loading.html",
        url=url
    )


# =========================================================
# SECURITY SCAN
# =========================================================

@app.route("/scan", methods=["POST"])
def scan():

    url = request.form.get("url", "").strip()

    try:

        # =================================================
        # HTTPS ANALYSIS
        # =================================================

        parsed_url = urlparse(url)

        if parsed_url.scheme == "https":

            https_secure = True

            https_status = "Secure connection (HTTPS)"

        else:

            https_secure = False

            https_status = "Not encrypted (HTTP)"


        # =================================================
        # HTTP REQUEST
        # =================================================

        response = requests.get(
            url,
            timeout=10,
            headers={
                "User-Agent": "WebSecurityScanner/1.0"
            }
        )


        # =================================================
        # HTML PARSER
        # =================================================

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )


        # =================================================
        # PAGE TITLE
        # =================================================

        if soup.title and soup.title.string:

            title = soup.title.string.strip()

        else:

            title = "No title found"


        # =================================================
        # FORM ANALYSIS
        # =================================================

        forms = soup.find_all("form")

        form_results = []

        for number, form in enumerate(
            forms,
            start=1
        ):

            method = form.get(
                "method",
                "GET"
            ).upper()

            action = form.get(
                "action",
                ""
            )

            if not action:

                action = url

            else:

                action = urljoin(
                    url,
                    action
                )

            password_fields = form.find_all(
                "input",
                {
                    "type": "password"
                }
            )

            has_password = (
                len(password_fields) > 0
            )

            action_scheme = urlparse(
                action
            ).scheme

            form_https = (
                action_scheme == "https"
            )

            form_results.append({

                "number": number,

                "method": method,

                "action": action,

                "has_password": has_password,

                "https": form_https

            })


        # =================================================
        # LINK ANALYSIS
        # =================================================

        all_links = soup.find_all(
            "a",
            href=True
        )

        internal_links = []

        external_links = []

        base_domain = urlparse(
            url
        ).netloc.lower()


        for link in all_links:

            href = link.get(
                "href",
                ""
            ).strip()

            # Ignore empty links
            if not href:
                continue

            # Ignore page fragments
            if href.startswith("#"):
                continue

            # Ignore email links
            if href.startswith("mailto:"):
                continue

            # Ignore telephone links
            if href.startswith("tel:"):
                continue

            # Convert relative URL to absolute URL
            absolute_url = urljoin(
                url,
                href
            )

            parsed_link = urlparse(
                absolute_url
            )

            link_domain = (
                parsed_link.netloc.lower()
            )

            if not link_domain:
                continue


            # Internal link
            if link_domain == base_domain:

                if absolute_url not in internal_links:

                    internal_links.append(
                        absolute_url
                    )


            # External link
            else:

                if absolute_url not in external_links:

                    external_links.append(
                        absolute_url
                    )


        # =================================================
        # HTTP HEADERS
        # =================================================

        headers = dict(
            response.headers
        )


        # =================================================
        # COOKIES
        # =================================================

        cookies = response.cookies

        cookie_results = []


        for cookie in cookies:

            cookie_results.append({

                "name": cookie.name,

                "secure": cookie.secure,

                "httponly":
                    "HttpOnly" in cookie._rest,

                "samesite":
                    cookie._rest.get(
                        "SameSite",
                        "Not specified"
                    )

            })


        # =================================================
        # TECHNOLOGY DETECTION
        # =================================================

        technologies = []

        html = response.text.lower()


        # -------------------------------------------------
        # WEB SERVER
        # -------------------------------------------------

        server = response.headers.get(
            "Server",
            ""
        )

        if server:

            technologies.append(
                f"Web Server: {server}"
            )


        # -------------------------------------------------
        # X-POWERED-BY
        # -------------------------------------------------

        powered_by = response.headers.get(
            "X-Powered-By",
            ""
        )

        if powered_by:

            technologies.append(
                f"Backend Indicator: {powered_by}"
            )


        # -------------------------------------------------
        # WORDPRESS
        # -------------------------------------------------

        if (
            "wp-content" in html
            or
            "wp-includes" in html
        ):

            technologies.append(
                "CMS Indicator: WordPress"
            )


        # -------------------------------------------------
        # BOOTSTRAP
        # -------------------------------------------------

        if "bootstrap" in html:

            technologies.append(
                "CSS Framework: Bootstrap"
            )


        # -------------------------------------------------
        # JQUERY
        # -------------------------------------------------

        if "jquery" in html:

            technologies.append(
                "JavaScript Library: jQuery"
            )


        # -------------------------------------------------
        # REACT
        # -------------------------------------------------

        if (
            "react" in html
            or
            "_reactroot" in html
            or
            "react-dom" in html
        ):

            technologies.append(
                "JavaScript Framework: React"
            )


        # -------------------------------------------------
        # ANGULAR
        # -------------------------------------------------

        if (
            "ng-version" in html
            or
            "angular" in html
        ):

            technologies.append(
                "JavaScript Framework: Angular"
            )


        # -------------------------------------------------
        # VUE.JS
        # -------------------------------------------------

        if (
            "vue" in html
            or
            "__vue__" in html
        ):

            technologies.append(
                "JavaScript Framework: Vue.js"
            )


        # -------------------------------------------------
        # PHP
        # -------------------------------------------------

        if (
            ".php" in html
            or
            "phpsessid" in html
        ):

            technologies.append(
                "Backend Indicator: PHP"
            )


        # -------------------------------------------------
        # CLOUDFLARE
        # -------------------------------------------------

        cf_ray = response.headers.get(
            "CF-RAY",
            ""
        )

        if (
            cf_ray
            or
            "cloudflare" in server.lower()
        ):

            technologies.append(
                "CDN / Security Indicator: Cloudflare"
            )


        # -------------------------------------------------
        # NGINX
        # -------------------------------------------------

        if "nginx" in server.lower():

            technologies.append(
                "Web Server: Nginx"
            )


        # -------------------------------------------------
        # APACHE
        # -------------------------------------------------

        if "apache" in server.lower():

            technologies.append(
                "Web Server: Apache"
            )


        # -------------------------------------------------
        # TECHNOLOGY NOT FOUND
        # -------------------------------------------------

        if not technologies:

            technologies.append(
                "No obvious technology indicators detected"
            )


        # =================================================
        # SECURITY HEADERS
        # =================================================

        security_headers = {

            "Strict-Transport-Security":
                "Helps enforce HTTPS connections",

            "Content-Security-Policy":
                "Helps control allowed content sources",

            "X-Frame-Options":
                "Helps protect against clickjacking",

            "X-Content-Type-Options":
                "Helps prevent MIME-type sniffing",

            "Referrer-Policy":
                "Controls referrer information",

            "Permissions-Policy":
                "Controls access to browser features"

        }


        security_results = {}


        for header, description in security_headers.items():

            if header in response.headers:

                security_results[header] = {

                    "status": "Present",

                    "description": description

                }

            else:

                security_results[header] = {

                    "status": "Missing",

                    "description": description

                }


        # =================================================
        # SECURITY SCORE
        # =================================================

        total_security_headers = len(
            security_headers
        )

        present_security_headers = sum(

            1

            for result in security_results.values()

            if result["status"] == "Present"

        )


        if total_security_headers > 0:

            security_score = (

                present_security_headers
                /
                total_security_headers

            ) * 100

        else:

            security_score = 0


        # =================================================
        # SEND DATA TO RESULT PAGE
        # =================================================

        return render_template(

            "result.html",

            url=url,

            status_code=response.status_code,

            title=title,

            forms_count=len(forms),

            form_results=form_results,

            links_count=len(all_links),

            internal_links=internal_links,

            external_links=external_links,

            cookies_count=len(cookies),

            cookie_results=cookie_results,

            headers=headers,

            technologies=technologies,

            security_results=security_results,

            security_score=round(
                security_score
            ),

            https_status=https_status,

            https_secure=https_secure

        )


    # =====================================================
    # ERROR HANDLING
    # =====================================================

    except requests.exceptions.Timeout:

        return """
        <h1>Request Timed Out</h1>

        <p>
        The website took too long to respond.
        </p>

        <a href="/">
        Try Again
        </a>
        """


    except requests.exceptions.ConnectionError:

        return """
        <h1>Connection Failed</h1>

        <p>
        The website could not be reached.
        </p>

        <p>
        Check the URL and your internet connection.
        </p>

        <a href="/">
        Try Again
        </a>
        """


    except requests.exceptions.RequestException as error:

        return f"""
        <h1>Scan Failed</h1>

        <p>
        {error}
        </p>

        <a href="/">
        Try Again
        </a>
        """


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )