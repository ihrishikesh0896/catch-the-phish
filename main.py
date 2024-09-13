from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
from urllib.parse import urlparse
import sqlite3
import socket
import whois
import ipaddress
from datetime import datetime, timedelta
from db import database # call local db file
import logging
import re
from urllib.parse import unquote

# FastAPI app instance
app = FastAPI()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Database connection
def db_connection():
    try:
        conn = sqlite3.connect('phish_tank.db')
        return conn
    except sqlite3.Error as e:
        logger.error(f"Error connecting to the database: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Database connection error")


# Pydantic model for URL submission
class UrlSubmission(BaseModel):
    url: str


# Unshorten URL function
def unshorten_url(url):
    try:
        response = requests.head(url, allow_redirects=False).headers['location']
        logger.info(f"Unshortened URL: {response}")
        return response
    except requests.RequestException as e:
        logger.error(f"Error unshortening URL: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail=f"Error unshortening URL: {str(e)}")


# Check if the input is an IP or domain
def is_ip_or_domain(input_str):
    try:
        ipaddress.ip_address(input_str)
        logger.info(f"Input is an IP address: {input_str}")
        return 'ip'
    except ValueError:
        logger.info(f"Input is a domain: {input_str}")
        return 'domain'


# Get domain info function
def get_domain_info(url):
    try:
        unshortened_url = unshorten_url(url)
        parsed_url = urlparse(unshortened_url)
        domain = parsed_url.netloc
        if is_ip_or_domain(domain) == 'domain':
            logger.info(f"Extracted domain: {domain}")
            return domain
        else:
            raise HTTPException(status_code=400, detail=f"Invalid domain: {domain}")
    except Exception as e:
        logger.error(f"Error extracting domain: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail=f"Error extracting domain: {str(e)}")


# Get IP address for domain or process if it's already an IP
def get_ip_address(domain_or_ip):
    if is_ip_or_domain(domain_or_ip) == 'domain':
        try:
            ip_address = socket.gethostbyname(domain_or_ip)
            logger.info(f"IP address for domain {domain_or_ip}: {ip_address}")
            return ip_address
        except socket.gaierror as e:
            logger.error(f"Error getting IP address for domain {domain_or_ip}: {e}", exc_info=True)
            return None  # Return None if IP resolution fails
    else:
        logger.info(f"Proceeding with provided IP: {domain_or_ip}")
        return domain_or_ip  # Return the IP if it's already an IP address


# Get Hosting details
def get_hosting_details(domain):
    try:
        w = whois.whois(domain)
        logger.info(f"Hosting details for domain {domain}: FOUND")
        return w
    except Exception as e:
        logger.error(f"Error getting hosting details for domain {domain}: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail=f"Error getting hosting details for domain {domain}")


# Simple scoring heuristic
import re
from urllib.parse import unquote


# Check for suspicious subdomains
def check_suspicious_subdomains(domain):
    subdomains = domain.split('.')
    if len(subdomains) > 3:  # Adjust threshold based on common practices
        logger.info(f"Suspicious subdomains found: {domain}")
        return True
    return False


# Check for phishing keywords in URL
def check_phishing_keywords(url):
    phishing_keywords = ["login", "secure", "account", "verify", "confirm", "update", "paypal"]
    for keyword in phishing_keywords:
        if keyword in url.lower():
            logger.info(f"Phishing keyword '{keyword}' found in URL: {url}")
            return True
    return False


# Check for direct IP address in the URL
def check_ip_in_url(url):
    try:
        ip = ipaddress.ip_address(url)
        logger.info(f"IP address used in URL: {url}")
        return True
    except ValueError:
        return False  # Not an IP address


# Check if URL is encoded (obfuscated)
def check_url_encoding(url):
    decoded_url = unquote(url)
    if url != decoded_url:
        logger.info(f"URL contains encoded characters: {url}")
        return True
    return False


# Check for URL length
def check_url_length(url):
    if len(url) > 75:  # Adjust threshold as necessary
        logger.info(f"Suspiciously long URL: {url}")
        return True
    return False


# Phishing score function
def score_url(url):
    score = 0

    # Check for suspicious subdomains
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if check_suspicious_subdomains(domain):
        score += 20

    # Check for phishing keywords
    if check_phishing_keywords(url):
        score += 30

    # Check for direct IP address in URL
    if check_ip_in_url(domain):
        score += 40

    # Check for encoded characters in the URL
    if check_url_encoding(url):
        score += 10

    # Check URL length
    if check_url_length(url):
        score += 10

    # Non-HTTPS URLs are penalized
    if "https" not in url:
        score += 20
        logger.info(f"Non-HTTPS URL penalized: {url}")

    logger.info(f"Score for URL {url}: {score}")
    return score


# Add URL to DB function
def add_url_to_db(url, domain, ip_address, hosting_provider, score, status):
    # Ensure no None values are inserted into the database
    ip_address = ip_address or ""  # Default to empty string if None
    hosting_provider = str(hosting_provider['registrar']) or ""  # Convert to string and default to empty string

    # Log the data being inserted
    logger.info(f"Trying to insert into DB: URL={url}, Domain={domain}, IP={ip_address}, "
                f"HostingProvider={hosting_provider}, Score={score}, Status={status}")

    # Validate data types
    if not isinstance(score, int):
        logger.error("Score must be an integer")
        raise ValueError("Score must be an integer")

    conn = db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO urls (original_url, domain, ip_address, hosting_provider, score, status, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (url, domain, ip_address, hosting_provider, score, status))
        conn.commit()
        logger.info(f"URL {url} added to database with status {status} and score {score}")
    except sqlite3.Error as e:
        logger.error(f"Error inserting URL into database: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Database insertion error")
    finally:
        conn.close()


# Get guilty URLs function
def get_guilty_urls():
    conn = db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM urls WHERE status="guilty"')
        rows = cursor.fetchall()
        logger.info(f"Retrieved guilty URLs: {rows}")
        return rows
    except sqlite3.Error as e:
        logger.error(f"Error retrieving guilty URLs from database: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Database query error")
    finally:
        conn.close()


# Automated release after 24 hours
def release_old_urls():
    conn = db_connection()
    try:
        cursor = conn.cursor()
        release_time = datetime.now() - timedelta(minutes=10)
        cursor.execute('''
        UPDATE urls
        SET status = "released"
        WHERE timestamp < ? AND status = "not guilty"
        ''', (release_time,))
        conn.commit()
        logger.info("Old URLs released from the database")
    except sqlite3.Error as e:
        logger.error(f"Error releasing old URLs: {e}", exc_info=True)
    finally:
        conn.close()


# FastAPI route to submit a URL
@app.post("/submit/")
async def submit_url(submission: UrlSubmission):
    try:
        url = submission.url
        domain_or_ip = get_domain_info(url)
        ip_address = get_ip_address(domain_or_ip)
        hosting_provider = get_hosting_details(domain_or_ip)
        score = score_url(url)
        status = "guilty" if score > 50 else "not guilty"
        add_url_to_db(url, domain_or_ip, ip_address, hosting_provider, score, status)
        return {"status": status, "score": score}
    except HTTPException as e:
        logger.error(f"Error during URL submission: {e.detail}", exc_info=True)
        raise e
    except Exception as e:
        logger.error(f"Unexpected error during URL submission: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Unexpected error occurred during URL submission")


# FastAPI route to retrieve guilty URLs
@app.get("/guilty/")
async def guilty_urls():
    try:
        urls = get_guilty_urls()
        return {"guilty_urls": urls}
    except HTTPException as e:
        logger.error(f"Error retrieving guilty URLs: {e.detail}", exc_info=True)
        raise e
    except Exception as e:
        logger.error(f"Unexpected error while retrieving guilty URLs: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Unexpected error occurred while retrieving guilty URLs")


# Background task for releasing old URLs
@app.on_event("startup")
async def startup_event():
    try:
        database.init_db()  # Initialize the database at startup
        # release_old_urls()  # Automatically release old URLs during startup
    except Exception as e:
        logger.error(f"Error during startup event: {e}", exc_info=True)
