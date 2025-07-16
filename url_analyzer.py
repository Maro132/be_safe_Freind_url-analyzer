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

def get_base_domain(domain):
    """
    Extracts the base domain from a given domain name.
    E.g., 'www.example.com' -> 'example.com', 'sub.example.co.uk' -> 'example.co.uk' (heuristic).
    This is a simple heuristic and might not cover all complex TLDs (e.g., .co.uk perfectly).
    """
    parts = domain.split('.')
    if len(parts) >= 2:
        # For most common TLDs (.com, .org, .net), taking the last two parts works.
        # For complex TLDs like .co.uk, this would still give 'co.uk' as base, which is not ideal,
        # but it's better than comparing full subdomains.
        return ".".join(parts[-2:])
    return domain # Fallback for very short or invalid domains

def levenshtein_distance(s1, s2):
    """
    Calculates the Levenshtein distance between two strings.
    This measures the minimum number of single-character edits (insertions, deletions, or substitutions)
    required to change one word into the other.
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


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
    Checks for potential typosquatting against a list of common domains using Levenshtein distance
    and specific common typo patterns.
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

    # Extract base domain for more accurate comparison
    input_base_domain = get_base_domain(domain)

    for common_domain in common_domains:
        common_base_domain = get_base_domain(common_domain)

        # 1. Exact match: If it's the exact common domain, it's not typosquatting.
        if domain == common_domain:
            return False, None

        # 2. Legitimate subdomain: If the input domain is a subdomain of a common domain, it's not typosquatting.
        #    e.g., 'en.wikipedia.org' for 'wikipedia.org'
        if domain.endswith("." + common_base_domain):
            return False, None
        
        # 3. Levenshtein Distance Check on Base Domains:
        #    This is the core "smart" check for typos.
        #    We compare the base domains. A distance of 1 or 2 is highly suspicious.
        distance = levenshtein_distance(input_base_domain, common_base_domain)
        if distance > 0 and distance <= 2: # Allow 1 or 2 character differences
            # Add additional checks to reduce false positives for very short domains or unrelated domains
            # For example, if 'a.com' vs 'b.com' has distance 1, it's not typosquatting.
            # We need to ensure there's a reasonable length to the domains being compared.
            if len(input_base_domain) >= 5 and len(common_base_domain) >= 5: # Only apply for reasonably long domains
                return True, f"The URL '{url}' might be typosquatting, mimicking '{common_domain}' (Levenshtein distance: {distance})."

        # 4. Common Typo Substitutions (e.g., l/1, o/0, missing dot)
        #    These are strong indicators regardless of Levenshtein distance for base domains.
        #    We apply these checks on the full domain for more coverage.
        
        # Remove dots for comparison if typo is missing dot (e.g., 'googlecom' vs 'google.com')
        domain_no_dot = domain.replace(".", "")
        common_domain_no_dot = common_domain.replace(".", "")

        if (domain_no_dot == common_domain_no_dot and domain != common_domain):
            return True, f"The URL '{url}' might be typosquatting, mimicking '{common_domain}' (missing dot typo)."

        # Character substitutions (e.g., goog1e.com)
        if (domain.replace('l', '1') == common_domain or
            domain.replace('o', '0') == common_domain or
            domain.replace('s', '5') == common_domain or
            domain.replace('a', '@') == common_domain):
            return True, f"The URL '{url}' might be typosquatting, mimicking '{common_domain}' (character substitution typo)."
        
        # Check for swapped adjacent characters (e.g., goolge.com) - simple heuristic
        if len(domain) == len(common_domain):
            diff_count = 0
            for i in range(len(domain)):
                if domain[i] != common_domain[i]:
                    diff_count += 1
            if diff_count == 2: # Check for exactly two differences, could be a swap
                # This is a very basic swap check, a real one would check positions
                pass # Not returning directly, let Levenshtein or other specific checks handle it

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

        # Get base domains for comparison to handle legitimate subdomain redirects
        initial_base_domain = get_base_domain(initial_domain)
        final_base_domain = get_base_domain(final_domain)

        # Only warn if redirection occurred AND it's to a different BASE domain
        if response.url != url and initial_base_domain != final_base_domain:
            return True, f"The URL redirects from '{initial_domain}' to a different base domain: '{final_domain}'. This could be risky."
        # No warning if it redirects within the same base domain (e.g., www to non-www, http to https, or subdomain to subdomain)
        # No warning if no redirection occurred at all (response.url == url)
    except ConnectionError as e: # Catch connection errors specifically
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc

        # Check if the error is due to a private IP address connection attempt
        is_private_ip = False
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if ip_obj.is_private:
                is_private_ip = True
        except ValueError:
            pass # Not an IP address or invalid IP

        # If it's a private IP and a connection error occurred, suppress this specific warning.
        # The check_ip_in_url function will still flag it as an IP address.
        if is_private_ip:
            return False, None # Suppress the network error warning for private IPs

        # If the error is due to name resolution (DNS failure) for a non-private IP
        if "Failed to resolve" in str(e) or "NameResolutionError" in str(e):
            return True, f"The URL's domain ('{hostname}') could not be resolved (DNS error). This might indicate a non-existent or malicious domain. Be cautious."
        else:
            # Other connection errors (e.g., host unreachable, connection refused) for non-private IPs
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
        ip_obj = ipaddress.ip_address(hostname)
        # We only flag it if it's not a private IP, as private IPs are handled differently in redirection check.
        # However, the user wants a warning for *any* IP in URL, so we keep this general.
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
        return False, f"Error checking with Google Safe Browsing API: {e}. This check could not be completed."
    except json.JSONDecodeError:
        # Handle cases where the API response is not valid JSON
        return False, "Failed to decode Google Safe Browsing API response. This check could not be completed."

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
    if is_malicious: # If Google Safe Browsing detected it as malicious
        warnings.append(f"🚨 DANGER: {safe_browsing_msg}")
    elif safe_browsing_msg and not is_malicious: # If there was an error message but not malicious
        warnings.append(f"⚠️ Warning: {safe_browsing_msg}")


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
            background-color: #1a1a1a; /* Light black / Very dark gray */
            color: #add8e6; /* Light blue */
            font-family: 'IBM Plex Mono', monospace;
        }
        .stApp {
            background-color: #1a1a1a; /* Light black / Very dark gray for the app container */
            color: #add8e6;
            padding: 20px; /* Overall padding for the app */
        }
        /* Customizing Streamlit's internal components for consistent theme */
        .css-fg4pbf, .css-1d3z93v, .stTextInput, .stButton, .stAlert, .stSpinner div {
            font-family: 'IBM Plex Mono', monospace !important;
        }
        .css-fg4pbf { /* Streamlit header - can be targetted more specifically */
            color: #32cd32; /* Lime Green */
        }
        .css-1d3z93v { /* Main content area, often the 'block' holding content */
            background-color: #2a2a2a; /* Slightly lighter dark gray for content area */
            padding: 30px; /* Increased padding */
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0, 255, 0, 0.1); /* More prominent glow shadow */
            margin-bottom: 20px; /* Space between sections */
        }
        .stTextInput > div > div > input {
            background-color: #0d0d0d; /* Even darker gray for input */
            color: #add8e6;
            border: 1px solid #0056b3; /* Darker blue border */
            border-radius: 8px; /* Slightly more rounded */
            padding: 12px; /* Increased padding */
            font-size: 1.1em; /* Slightly larger font */
            transition: border-color 0.3s ease, box-shadow 0.3s ease;
        }
        .stTextInput > div > div > input:focus {
            border-color: #32cd32; /* Green border on focus */
            box-shadow: 0 0 0 2px rgba(50, 205, 50, 0.5); /* Green glow on focus */
            outline: none;
        }
        .stButton > button {
            background-color: #0056b3; /* Darker blue button */
            color: white;
            border: none;
            border-radius: 8px; /* Slightly more rounded */
            padding: 12px 25px; /* Increased padding */
            cursor: pointer;
            transition: background-color 0.3s ease, transform 0.2s ease; /* Smooth hover and press effect */
            font-size: 1.1em;
            font-weight: bold;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
        }
        .stButton > button:hover {
            background-color: #007bff; /* Lighter blue on hover */
            transform: translateY(-2px); /* Slight lift effect */
        }
        .stButton > button:active {
            transform: translateY(0); /* Press effect */
        }
        .warning-text {
            color: #ff4500; /* OrangeRed for warnings */
            font-weight: bold;
        }
        .danger-text {
            color: #dc3545; /* Red for dangers */
            font-weight: bold; /* Make danger messages stand out */
            font-size: 1.1em; /* Slightly larger for danger */
        }
        .safe-text {
            color: #28a745; /* Green for safe */
            font-weight: bold;
        }
        h1, h2, h3, h4, h5, h6 {
            font-family: 'IBM Plex Mono', monospace;
            color: #32cd32; /* Lime Green for headers */
            text-shadow: 1px 1px 2px rgba(0, 255, 0, 0.3); /* Subtle glow for headers */
            margin-bottom: 15px; /* Space below headers */
        }
        p {
            margin-bottom: 10px; /* Space below paragraphs */
        }
        hr {
            border-top: 1px dashed #0056b3;
            margin-top: 20px;
            margin-bottom: 20px;
        }
        /* Spinner color */
        .stSpinner > div > div {
            border-top-color: #32cd32 !important; /* Green spinner */
        }
        </style>
        """, unsafe_allow_html=True
    )

    # Main title and subtitle with custom styles
    st.markdown(
        """
        <h1 style='text-align: left; color: #32cd32; font-size: 40px; padding-left: 0px; padding-top: 0px; margin-bottom: 5px;'>
            be_<span style='font-size: 0.7em;'>$</span>afe_friend!
        </h1>
        <p style='text-align: left; color: #add8e6; font-size: 18px; padding-left: 0px; margin-top: 0;'>
            Your Digital Guardian
        </p>
        <hr style='border-top: 1px dashed #0056b3; margin-top: 10px; margin-bottom: 30px;'>
        """, unsafe_allow_html=True
    )

    st.write("Hello friend! Enter a URL below to check its safety.")

    # Input field for the URL
    user_url = st.text_input("Enter URL to analyze:", "https://").strip()

    # Analyze button
    if st.button("Analyze URL"):
        if not user_url: # Check if empty after stripping
            st.error("Please enter a URL to analyze.")
        elif not user_url.startswith(("http://", "https://")):
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
