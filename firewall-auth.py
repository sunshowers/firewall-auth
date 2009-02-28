#!/usr/bin/python

import httplib
import urllib
import urlparse
import re
import threading
from optparse import OptionParser
import sys
import logging

def FirewallKeepAlive(url):
  logging.getLogger("FirewallLogger").info("Sending request to keep alive")
  # Connect to the firewall
  conn = httplib.HTTPConnection(url.netloc)
  conn.request("GET", url.path + "?" + url.query)
  
  # Set a timer
  t = threading.Timer(1600.0, FirewallKeepAlive, [url])
  t.start()


def FirewallAuth(username, password):
  # Connect to Google, see if we can connect or not
  logger = logging.getLogger("FirewallLogger")
  conn = httplib.HTTPConnection("www.google.com:80")
  conn.request("GET", "/")
  response = conn.getresponse()
  # If the response is 401, then we need to auth
  if (response.status == 401):
    data = response.read()
    conn.close()
    
    # Look for the right magic value in the data
    match = re.search(r"VALUE=\"([0-9a-f]+)\"", data)
    magicString = match.group(1)
    logger.debug("The magic string is:", magicString)
    
    # Now construct a POST request
    params = urllib.urlencode({'username': username, 'password': password,
                               'magic': magicString, '4Tredir': '/'})
    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "Accept": "text/plain"}
    
    postConn = httplib.HTTPConnection("www.google.com:80")
    postConn.request("POST", "/", params, headers)
    
    # Get the response
    postResponse = postConn.getresponse()
    
    postData = postResponse.read()
    postConn.close()
    
    # Look for the keepalive URL
    keepaliveMatch = re.search(r"location.href=\"(.+?)\"", postData)
    if keepaliveMatch is None:
      # Whoops, unsuccessful -- probably the username and password didn't match
      logger.fatal("Authentication unsuccessful, check your username and password")
      return 3
    
    keepaliveURL = keepaliveMatch.group(1)
    
    logger.info("The keep alive URL is: " + keepaliveURL)
    logger.debug(postData)
    FirewallKeepAlive(urlparse.urlparse(keepaliveURL))
  
  else:
    logger.fatal(("Server returned %d %s, so we cannot proceed. Are you " +
                 "already authenticated?") %
                 (response.status, httplib.responses[response.status]))
    return 2

"""
Main function
"""
def main(argv = None):
  if argv is None:
    argv = sys.argv[1:]
  
  # First generate help syntax
  usage = "Usage: %prog [options] username password"
  parser = OptionParser(usage = usage)
  parser.add_option("-v", "--verbose", action = "store_true", dest = "verbose",
                    help = "Print lots of debugging information")
  
  # Parse arguments
  (options, args) = parser.parse_args(argv)
  
  if len(args) != 2:
    parser.error("invalid number of arguments")
    return 1
  
  logger = logging.getLogger("FirewallLogger")
  logger.setLevel(logging.DEBUG)
  handler = logging.StreamHandler()
  if options.verbose:
    handler.setLevel(logging.DEBUG)
  else:
    handler.setLevel(logging.INFO)
  
  formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
  handler.setFormatter(formatter)
  logger.addHandler(handler)
  
  # Try authenticating!
  return FirewallAuth(args[0], args[1])

if __name__ == "__main__":
  sys.exit(main())
