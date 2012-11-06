#!/usr/bin/python

# Copyright (c) 2009 Siddharth Agarwal
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

import getpass
import httplib
import urllib
import urlparse
import re
from optparse import OptionParser
import sys
import logging
import time
import atexit
import socket
import gc

class FirewallState:
  Start, LoggedIn, End = range(3)

# Globals, set right in the beginning
username = None
password = None

def start_func():
  """
  This is called when we're in the initial state. If we're already logged in, we
  can't do anything much. If we're not, we should transition to the
  not-logged-in state.
  """
  ERROR_RETRY_SECS = 5
  LOGGED_IN_RETRY_SECS = 5
  logger = logging.getLogger("FirewallLogger")

  try:
    loginstate, data = login()
  except (httplib.HTTPException, socket.error) as e:
    logger.info("Exception |%s| while trying to log in. Retrying in %d seconds." %
                (e, ERROR_RETRY_SECS))
    return (FirewallState.Start, ERROR_RETRY_SECS, None)

  # Check whether we're logged in
  if loginstate == LoginState.AlreadyLoggedIn:
    logger.info("You're already logged in (response code %d). Retrying in %d seconds." %
                (data, LOGGED_IN_RETRY_SECS))
    return (FirewallState.Start, LOGGED_IN_RETRY_SECS, None)
  elif loginstate == LoginState.InvalidCredentials:
    # Not much we can do.
    return (FirewallState.End, 0, [3])
  else:
    # Yay, we logged in.
    return (FirewallState.LoggedIn, 0, [data])

def logged_in_func(keepaliveurl):
  """
  Keep the firewall authentication alive by pinging a keepalive URL every few
  seconds. If there are any connection problems, keep trying with the same
  URL. If the keepalive URL doesn't work any more, go back to the start state.
  """
  logger = logging.getLogger("FirewallLogger")
  ERROR_RETRY_SECS = 5
  LOGGED_IN_SECS = 200
  try:
    keep_alive(keepaliveurl)
  except httplib.BadStatusLine:
    logger.info("The keepalive URL %s doesn't work. Attempting to log in again." %
                keepaliveurl.geturl())
    return (FirewallState.Start, 0, None)
  except (httplib.HTTPException, socket.error) as e:
    logger.info("Exception |%s| while trying to keep alive. Retrying in %d seconds." %
                (e, ERROR_RETRY_SECS))
    return (FirewallState.LoggedIn, ERROR_RETRY_SECS, [keepaliveurl])

  # OK, the URL worked. That's good.
  return (FirewallState.LoggedIn, LOGGED_IN_SECS, [keepaliveurl])

state_functions = {
  FirewallState.Start: start_func,
  FirewallState.LoggedIn: logged_in_func,
  FirewallState.End: sys.exit
}

def run_state_machine():
  """
  Runs the state machine defined above.
  """
  state = FirewallState.Start
  args = None
  sleeptime = 0
  def atexit_logout():
    """
    Log out from firewall authentication. This is supposed to run whenever the
    program exits.
    """
    logger = logging.getLogger("FirewallLogger")
    if state == FirewallState.LoggedIn:
      url = args[0]
      logouturl = urlparse.ParseResult(url.scheme, url.netloc, "/logout",
                                       url.params, url.query, url.fragment)
      try:
        logger.info("Logging out with URL %s" % logouturl.geturl())
        conn = httplib.HTTPSConnection(logouturl.netloc)
        conn.request("GET", logouturl.path + "?" + logouturl.query)
        response = conn.getresponse()
        response.read()
      except (httplib.HTTPException, socket.error) as e:
        # Just print an error message
        logger.info("Exception |%s| while logging out." % e)
      finally:
        conn.close()

  atexit.register(atexit_logout)

  while True:
    statefunc = state_functions[state]
    if args is None:
      state, sleeptime, args = statefunc()
    else:
      state, sleeptime, args = statefunc(*args)
    if sleeptime > 0:
      time.sleep(sleeptime)

class LoginState:
  AlreadyLoggedIn, InvalidCredentials, Successful = range(3)

def login():
  """
  Attempt to log in. Returns AlreadyLoggedIn if we're already logged in,
  InvalidCredentials if the username and password given are incorrect, and
  Successful if we have managed to log in. Throws an exception if an error
  occurs somewhere along the process.
  """
  logger = logging.getLogger("FirewallLogger")
  # Find out where to auth
  try:
    conn = httplib.HTTPConnection("74.125.236.51:80")
    conn.request("GET", "/")
    response = conn.getresponse()
    # 303 leads to the auth page, so it means we're not logged in
    if (response.status != 303):
      return (LoginState.AlreadyLoggedIn, response.status)

    authlocation = response.getheader("Location")
  finally:
    conn.close()

  logger.info("The auth location is: %s" % authlocation)

  # Make a connection to the auth location
  parsedauthloc = urlparse.urlparse(authlocation)
  try:
    authconn = httplib.HTTPSConnection(parsedauthloc.netloc)
    authconn.request("GET", parsedauthloc.path + "?" + parsedauthloc.query)
    authResponse = authconn.getresponse()
    data = authResponse.read()
  finally:
    authconn.close()

  # Look for the right magic value in the data
  match = re.search(r"VALUE=\"([0-9a-f]+)\"", data)
  magicString = match.group(1)
  logger.debug("The magic string is: " + magicString)

  # Now construct a POST request
  params = urllib.urlencode({'username': username, 'password': password,
                             'magic': magicString, '4Tredir': '/'})
  headers = {"Content-Type": "application/x-www-form-urlencoded",
             "Accept": "text/plain"}

  try:
    postconn = httplib.HTTPSConnection(parsedauthloc.netloc)
    postconn.request("POST", "/", params, headers)

    # Get the response
    postResponse = postconn.getresponse()
    postData = postResponse.read()
  finally:
    postconn.close()

  # Look for the keepalive URL
  keepaliveMatch = re.search(r"location.href=\"(.+?)\"", postData)
  if keepaliveMatch is None:
    # Whoops, unsuccessful -- probably the username and password didn't match
    logger.fatal("Authentication unsuccessful, check your username and password.")
    return (LoginState.InvalidCredentials, None)

  keepaliveURL = keepaliveMatch.group(1)

  logger.info("The keep alive URL is: " + keepaliveURL)
  logger.debug(postData)
  return (LoginState.Successful, urlparse.urlparse(keepaliveURL))

def keep_alive(url):
  """
  Attempt to keep the connection alive by pinging a URL.
  """
  logger = logging.getLogger("FirewallLogger")
  logger.info("Sending request to keep alive.")
  # Connect to the firewall
  try:
    conn = httplib.HTTPSConnection(url.netloc)
    conn.request("GET", url.path + "?" + url.query)
    # This line raises an exception if the URL stops working. We catch it in
    # logged_in_func.
    response = conn.getresponse()

    logger.debug(str(response.status))
    logger.debug(response.read())
  finally:
    conn.close()
    gc.collect()

def get_credentials(args):
  """
  Get the username and password, either from command line args or interactively.
  """
  username = None
  if len(args) == 0:
    # Get the username from the input
    print "Username: ",
    username = sys.stdin.readline()[:-1]
  else:
    # First member of args
    username = args[0]

  password = None
  if len(args) <= 1:
    # Read the password without echoing it
    password = getpass.getpass()
  else:
    password = args[1]

  return (username, password)

def init_logger(options):
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

"""
Main function
"""
def main(argv = None):
  if argv is None:
    argv = sys.argv[1:]

  # First generate help syntax
  usage = "Usage: %prog [options] [username [password]]"
  parser = OptionParser(usage = usage)
  parser.add_option("-v", "--verbose", action = "store_true", dest = "verbose",
                    help = "Print lots of debugging information")

  # Parse arguments
  (options, args) = parser.parse_args(argv)

  if len(args) > 2:
    parser.error("too many arguments")
    return 1

  init_logger(options)

  # Try authenticating!
  global username, password
  username, password = get_credentials(args)
  run_state_machine()
  return 0

if __name__ == "__main__":
  sys.exit(main())
