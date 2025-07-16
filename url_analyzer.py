import requests
from urllib.parse import urlparse
import re
import ipaddress
import json
import os
import streamlit as st
from requests.exceptions import ConnectionError, RequestException # Import specific exception types

# --- IMPORTANT SECURITY WARNING ---
# You have requested to hardcode your Google Safe Browsing API key directly into the code.
# This is generally NOT recommended for production applications or when sharing code publicly
# (e.g., on GitHub) as it exposes your key.
# For better security, it's recommended to use Streamlit's secrets management (.streamlit/secrets.toml)
# or environment variables, as discussed previously.
#
# Your provided API Key: AIzaSyDXadmvnbrYgM50493279uevflUlq168fA
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyDXadmvnbrYgM50493279uevflUlq168fA"

# --- be_$afe_friend! Core Functions ---

def check_url_shortener(url):
    """
    Checks if a URL is likely a shortened URL and tries to resolve it.
    Returns (True, message) if shortened, (False, None) otherwise.
    """
    shortener_domains = [
        "bit.ly", "tinyurl.com", "is.gd", "goo.gl", "ow.ly", "buff.ly",
        "t.co", "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly", "url.ie"
    ]
    parsed_url = urlparse(url)
    # Check if the domain is a known shortener
    if parsed_url.netloc in shortener_domains:
        try:
            # Attempt to get the final URL after redirects
            response = requests.head(url, allow_redirects=True, timeout=5)
            final_url = response.url
            if final_url != url:
                return True, f"The URL appears to be shortened. Original URL might be: {final_url}"
            else:
                return True, "The URL appears to be shortened." # Could not resolve, but still a shortener
        except requests.exceptions.RequestException:
            # Handle network errors or timeouts during resolution
            return True, "The URL appears to be shortened, but could not resolve original URL due to an error."
    return False, None

def check_typosquatting(url):
    """
    Checks for potential typosquatting against a list of common domains.
    This is a basic heuristic check; more advanced methods exist (e.g., Levenshtein distance).
    Returns (True, message) if potential typosquatting, (False, None) otherwise.
    """
    common_domains = [
        "google.com", "facebook.com", "amazon.com", "microsoft.com",
        "apple.com", "paypal.com", "twitter.com", "instagram.com",
        "youtube.com", "wikipedia.org", "linkedin.com", "netflix.com",
        "reddit.com", "ebay.com", "yahoo.com"
    ]
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower().replace("www.", "") # Normalize domain

    for common_domain in common_domains:
        cd_no_dot = common_domain.replace(".", "")
        domain_no_dot = domain.replace(".", "")

        # Simple common typo checks (e.g., l/1, o/0, missing dot)
        if (domain.replace('l', '1') == common_domain or
            domain.replace('o', '0') == common_domain or
            domain.replace('s', '5') == common_domain or
            domain.replace('a', '@') == common_domain or
            (domain.replace('.', '') == common_domain.replace('.', '') and domain != common_domain) # e.g., googlecom vs google.com
        ):
            return True, f"The URL '{url}' might be typosquatting, mimicking '{common_domain}'."

        # Basic check for similar length and content after removing non-alphanumeric chars
        clean_domain = re.sub(r'[^a-z0-9]', '', domain)
        clean_common = re.sub(r'[^a-z0-9]', '', common_domain.lower().replace("www.", ""))

        if len(clean_domain) > 3 and len(clean_common) > 3:
            # Check for close matches or minor variations (e.g., google.com.net)
            if clean_common in clean_domain or clean_domain in clean_common:
                # Avoid false positives where a legitimate domain contains another (e.g., google.com.analytics.com)
                if not (domain.endswith(common_domain) or common_domain.endswith(domain)):
                    if abs(len(clean_domain) - len(clean_common)) <= 2: # Check if lengths are very close
                        return True, f"The URL '{url}' might be typosquatting, mimicking '{common_domain}'."

    return False, None

def check_redirection(url):
    """
    Checks if a URL performs an immediate redirection to a different domain or if it's unreachable.
    Returns (True, message) if redirection detected or unreachable, (False, None) otherwise.
    """
    try:
        # Use GET to follow redirects
        response = requests.get(url, allow_redirects=True, timeout=5)
        initial_domain = urlparse(url).netloc
        final_domain = urlparse(response.url).netloc

        if initial_domain != final_domain:
            return True, f"The URL redirects from '{initial_domain}' to a different domain: '{final_domain}'. This could be risky."
        elif response.url != url:
            # Redirection happened but to the same domain (e.g., http to https, or different path)
            return True, f"The URL redirects to: {response.url}. While the domain is the same, be cautious as redirection occurred."
    except ConnectionError as e: # Catch connection errors specifically
        # Check if the error is due to name resolution (DNS failure)
        if "Failed to resolve" in str(e) or "NameResolutionError" in str(e):
            return True, f"The URL's domain ('{urlparse(url).netloc}') could not be resolved (DNS error). This might indicate a non-existent or malicious domain. Be cautious."
        else:
            # Other connection errors (e.g., host unreachable, connection refused)
            return True, f"Could not connect to the URL due to a network error: {e}. Be cautious."
    except RequestException as e: # Catch other general request-related errors
        return True, f"Could not check for redirection due to an unexpected error: {e}. Be cautious."
    return False, None

def check_http_vs_https(url):
    """
    Checks if the URL uses HTTP instead of HTTPS.
    Returns (True, message) if HTTP, (False, None) otherwise.
    """
    if url.startswith("http://"):
        return True, "The URL uses HTTP instead of HTTPS. HTTPS is more secure."
    return False, None

def check_ip_in_url(url):
    """
    Checks if the URL's hostname is an IP address instead of a domain name.
    Returns (True, message) if IP address found, (False, None) otherwise.
    """
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc
    try:
        # ipaddress module can parse and validate IP addresses
        ipaddress.ip_address(hostname)
        return True, f"The URL uses an IP address ({hostname}) instead of a domain name. This can be suspicious."
    except ValueError:
        # Not a valid IP address
        return False, None

def check_google_safe_browsing(url):
    """
    Uses Google Safe Browsing API to check if the URL is malicious.
    Returns (True, message) if malicious, (False, None) otherwise.
    """
    # Check if API key is available
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        # This case should ideally not be reached if key is hardcoded, but good for robustness
        return False, "Google Safe Browsing API key is missing. Skipping check."

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    headers = {"Content-Type": "application/json"}
    payload = {
        "client": {
            "clientId": "be-safe-friend",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION", "THREAT_TYPE_UNSPECIFIED"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        # Make the POST request to the Safe Browsing API
        response = requests.post(api_url, headers=headers, data=json.dumps(payload), timeout=10)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        result = response.json()

        if "matches" in result:
            # If matches are found, it means the URL is malicious
            threat_type = result['matches'][0]['threatType'].replace('_', ' ').title()
            return True, f"Google Safe Browsing detected the URL as: {threat_type}"
        else:
            # No matches found, URL is clean according to Safe Browsing
            return False, None
    except requests.exceptions.RequestException as e:
        # Handle errors during the API call
        return False, f"Error checking with Google Safe Browsing: {e}. Be cautious."
    except json.JSONDecodeError:
        # Handle cases where the API response is not valid JSON
        return False, "Failed to decode Google Safe Browsing API response. Be cautious."

# --- Main Analysis Function ---

def analyze_url(url):
    """
    Analyzes a given URL for various potential risks and returns a list of warnings.
    Each warning is a string describing the detected risk.
    """
    warnings = []

    # Run each check and append warnings if found
    is_shortened, shortener_msg = check_url_shortener(url)
    if is_shortened:
        warnings.append(f"⚠️ Warning: {shortener_msg} (The link has been shortened).")

    is_typosquatting, typosquatting_msg = check_typosquatting(url)
    if is_typosquatting:
        warnings.append(f"⚠️ Warning: {typosquatting_msg} (Data theft might occur as the link is modified from the original company name).")

    is_redirecting, redirection_msg = check_redirection(url)
    if is_redirecting:
        # The message from check_redirection is now more specific
        warnings.append(f"⚠️ Warning: {redirection_msg}")

    is_http, http_msg = check_http_vs_https(url)
    if is_http:
        warnings.append(f"⚠️ Warning: {http_msg} (Uses HTTP instead of the more secure HTTPS).")

    is_ip_url, ip_url_msg = check_ip_in_url(url)
    if is_ip_url:
        warnings.append(f"⚠️ Warning: {ip_url_msg} (This could lead to data theft).")

    # This is a critical check, so it's placed last and gives a "DANGER" message
    is_malicious, safe_browsing_msg = check_google_safe_browsing(url)
    if is_malicious:
        warnings.append(f"🚨 DANGER: {safe_browsing_msg}")

    return warnings

# --- Streamlit UI ---

def main_streamlit_app():
    # Set basic page configuration
    st.set_page_config(page_title="be_$afe_friend!", page_icon="🛡️")

    # Apply custom CSS for Mr. Robot theme (colors, fonts)
    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&display=swap');
        body {
            background-color: #000000; /* Pure Black background */
            color: #add8e6; /* Light blue */
            font-family: 'IBM Plex Mono', monospace;
        }
        .stApp {
            background-color: #000000; /* Pure Black background for the app container */
            color: #add8e6;
        }
        /* Customizing Streamlit's internal components for consistent theme */
        .css-fg4pbf, .css-1d3z93v, .stTextInput, .stButton, .stAlert {
            font-family: 'IBM Plex Mono', monospace !important;
        }
        .css-fg4pbf { /* Streamlit header - can be targetted more specifically */
            color: #32cd32; /* Lime Green */
        }
        .css-1d3z93v { /* Main content area, often the 'block' holding content */
            background-color: #1a2a3a; /* Slightly lighter dark blue */
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2); /* Subtle shadow for depth */
        }
        .stTextInput > div > div > input {
            background-color: #001a33; /* Even darker blue for input */
            color: #add8e6;
            border: 1px solid #0056b3; /* Darker blue border */
            border-radius: 5px;
            padding: 10px;
        }
        .stButton > button {
            background-color: #0056b3; /* Darker blue button */
            color: white;
            border: none;
            border-radius: 5px;
            padding: 10px 20px;
            cursor: pointer;
            transition: background-color 0.3s ease; /* Smooth hover effect */
        }
        .stButton > button:hover {
            background-color: #007bff; /* Lighter blue on hover */
        }
        .warning-text {
            color: #ff4500; /* OrangeRed for warnings */
        }
        .danger-text {
            color: #dc3545; /* Red for dangers */
            font-weight: bold; /* Make danger messages stand out */
        }
        .safe-text {
            color: #28a745; /* Green for safe */
        }
        h1, h2, h3, h4, h5, h6 {
            font-family: 'IBM Plex Mono', monospace;
            color: #32cd32; /* Lime Green for headers */
            text-shadow: 1px 1px 2px rgba(0, 255, 0, 0.3); /* Subtle glow for headers */
        }
        .stAlert {
            background-color: #1a2a3a;
            color: #add8e6;
            border-left: 5px solid; /* Add a colored border to alerts */
            border-color: #0056b3; /* Default alert border color */
        }
        .stAlert.error {
            border-color: #dc3545; /* Red border for errors */
        }
        .stAlert.warning {
            border-color: #ffc107; /* Yellow border for warnings */
        }
        .stAlert.success {
            border-color: #28a745; /* Green border for success */
        }
        </style>
        """, unsafe_allow_html=True)

    # Main title and subtitle with custom styles
    # Changed text-align to left and added padding for top-left positioning
    st.markdown(
        """
        <h1 style='text-align: left; color: #32cd32; font-size: 40px; padding-left: 20px; padding-top: 10px;'>
            be<sub><span style='font-size: 0.7em;'>$</span></sub>afe_friend!
        </h1>
        <p style='text-align: left; color: #add8e6; font-size: 18px; padding-left: 20px;'>
            Your Digital Guardian
        </p>
        <hr style='border-top: 1px dashed #0056b3;'>
        """, unsafe_allow_html=True
    )

    st.write("Hello Maro! Enter a URL below to check its safety.")

    # Input field for the URL
    user_url = st.text_input("Enter URL to analyze:", "https://")

    # Analyze button
    if st.button("Analyze URL"):
        if not user_url or not user_url.startswith(("http://", "https://")):
            st.error("Please enter a valid URL, including http:// or https://")
        else:
            # Show a spinner while analyzing
            with st.spinner("Analyzing URL... This might take a moment."):
                results = analyze_url(user_url)

            st.markdown("---")
            st.markdown("### Analysis Results")

            # Display results
            if results:
                for warning in results:
                    if "DANGER" in warning:
                        st.markdown(f"<p class='danger-text'>{warning}</p>", unsafe_allow_html=True)
                    else:
                        st.markdown(f"<p class='warning-text'>{warning}</p>", unsafe_allow_html=True)
            else:
                st.markdown("<p class='safe-text'>✅ Good news! The URL appears to be safe and free from common manipulations.</p>", unsafe_allow_html=True)
            st.markdown("---")

# This ensures that main_streamlit_app() runs only when the script is executed directly
if __name__ == "__main__":
    main_streamlit_app()
