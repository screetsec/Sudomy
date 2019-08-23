#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of webscreenshot.
#
# Copyright (C) 2018, Thomas Debize <tdebize at mail.com>
# All rights reserved.
#
# webscreenshot is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# webscreenshot is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with webscreenshot.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import re
import os
import sys
import subprocess
import datetime
import time
import signal
import multiprocessing
import itertools
import shlex
import logging
import errno
import argparse

# Python 2 and 3 compatibility
if (sys.version_info < (3, 0)):
    os_getcwd = os.getcwdu
    izip = itertools.izip
    
else:
    os_getcwd = os.getcwd
    izip = zip

# Script version
VERSION = '2.4'


# Options definition
parser = argparse.ArgumentParser()

main_grp = parser.add_argument_group('Main parameters')
main_grp.add_argument('URL', help = 'Single URL target given as a positional argument', nargs = '?')
main_grp.add_argument('-i', '--input-file', help = '<INPUT_FILE> text file containing the target list. Ex: list.txt')
main_grp.add_argument('-o', '--output-directory', help = '<OUTPUT_DIRECTORY> (optional): screenshots output directory (default \'./screenshots/\')')
main_grp.add_argument('-w', '--workers', help = '<WORKERS> (optional): number of parallel execution workers (default 4)', default = 4)
main_grp.add_argument('-v', '--verbosity', help = '<VERBOSITY> (optional): verbosity level, repeat it to increase the level { -v INFO, -vv DEBUG } (default verbosity ERROR)', action = 'count', default = 0)

screenshot_grp = parser.add_argument_group('Screenshot parameters')
screenshot_grp.add_argument('-r', '--renderer', help = '<RENDERER> (optional): renderer to use among \'phantomjs\' (legacy but best results), \'chrome\', \'chromium\', \'firefox\' (version > 57) (default \'phantomjs\')', choices = ['phantomjs', 'chrome', 'chromium', 'firefox'], type=str.lower, default = 'phantomjs')
screenshot_grp.add_argument('--renderer-binary', help = '<RENDERER_BINARY> (optional): path to the renderer executable if it cannot be found in $PATH')
screenshot_grp.add_argument('--no-xserver', help = '<NO_X_SERVER> (optional): if you are running without an X server, will use xvfb-run to execute the renderer', action = 'store_true', default = False)
screenshot_grp.add_argument('--window-size', help = '<WINDOW_SIZE> (optional): width and height of the screen capture (default \'1200,800\')', default = '1200,800')

proc_grp = parser.add_argument_group('Input processing parameters')
proc_grp.add_argument('-p', '--port', help = '<PORT> (optional): use the specified port for each target in the input list. Ex: -p 80')
proc_grp.add_argument('-s', '--ssl', help = '<SSL> (optional): enforce ssl for every connection', action = 'store_true', default = False)
proc_grp.add_argument('-m', '--multiprotocol', help = '<MULTIPROTOCOL> (optional): perform screenshots over HTTP and HTTPS for each target', action = 'store_true', default = False) 

http_grp = parser.add_argument_group('HTTP parameters')
http_grp.add_argument('-c', '--cookie', help = '<COOKIE_STRING> (optional): cookie string to add. Ex: -c "JSESSIONID=1234; YOLO=SWAG"')
http_grp.add_argument('-a', '--header', help = '<HEADER> (optional): custom or additional header. Repeat this option for every header. Ex: -a "Host: localhost" -a "Foo: bar"', action = 'append')

http_grp.add_argument('-u', '--http-username', help = '<HTTP_USERNAME> (optional): specify a username for HTTP Basic Authentication.')
http_grp.add_argument('-b', '--http-password', help = '<HTTP_PASSWORD> (optional): specify a password for HTTP Basic Authentication.')

conn_grp = parser.add_argument_group('Connection parameters')
conn_grp.add_argument('-P', '--proxy', help = '<PROXY> (optional): specify a proxy. Ex: -P http://proxy.company.com:8080')
conn_grp.add_argument('-A', '--proxy-auth', help = '<PROXY_AUTH> (optional): provides authentication information for the proxy. Ex: -A user:password')
conn_grp.add_argument('-T', '--proxy-type', help = '<PROXY_TYPE> (optional): specifies the proxy type, "http" (default), "none" (disable completely), or "socks5". Ex: -T socks')
conn_grp.add_argument('-t', '--timeout', help = '<TIMEOUT> (optional): renderer execution timeout in seconds (default 30 sec)', default = 30)

# renderer binaries, hoping to find it in a $PATH directory
## Be free to change them to your own full-path location 
PHANTOMJS_BIN = 'phantomjs'
CHROME_BIN = 'google-chrome'
CHROMIUM_BIN = 'chromium'
FIREFOX_BIN = 'firefox'
XVFB_BIN = "xvfb-run -a"

WEBSCREENSHOT_JS = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), './webscreenshot.js'))
SCREENSHOTS_DIRECTORY = os.path.abspath(os.path.join(os_getcwd(), './screenshots/'))

# Logger definition
LOGLEVELS = {0 : 'ERROR', 1 : 'INFO', 2 : 'DEBUG'}
logger_output = logging.StreamHandler(sys.stdout)
logger_output.setFormatter(logging.Formatter('[%(levelname)s][%(name)s] %(message)s'))

logger_gen = logging.getLogger("General")
logger_gen.addHandler(logger_output)

# Macros
SHELL_EXECUTION_OK = 0
SHELL_EXECUTION_ERROR = -1
PHANTOMJS_HTTP_AUTH_ERROR_CODE = 2

# Handful patterns
p_ipv4_elementary = '(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})'
p_domain = '[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6}'
p_port = '\d{0,5}'
p_resource = '(?:/(?P<res>.*))?'

full_uri_domain = re.compile('^(?P<protocol>http(?:|s))://(?P<host>%s|%s)(?::(?P<port>%s))?%s$' % (p_domain, p_ipv4_elementary, p_port, p_resource))

fqdn_and_port = re.compile('^(?P<host>%s):(?P<port>%s)%s$' % (p_domain, p_port, p_resource))
fqdn_only = re.compile('^(?P<host>%s)%s$' % (p_domain, p_resource))

ipv4_and_port = re.compile('^(?P<host>%s):(?P<port>%s)%s' % (p_ipv4_elementary, p_port, p_resource))
ipv4_only = re.compile('^(?P<host>%s)%s$' % (p_ipv4_elementary, p_resource))

entry_from_csv = re.compile('^(?P<host>%s|%s)\s+(?P<port>\d+)$' % (p_domain, p_ipv4_elementary))

# Handful functions
def init_worker():
    """ 
        Tell the workers to ignore a global SIGINT interruption
    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    
def kill_em_all(signal, frame):
    """
        Terminate all processes while capturing a SIGINT from the user
    """
    logger_gen.info('CTRL-C received, exiting')
    sys.exit(0)
    
def shell_exec(url, command, options):
    """
        Execute a shell command following a timeout
        Taken from http://howto.pui.ch/post/37471155682/set-timeout-for-a-shell-command-in-python
    """
    global SHELL_EXECUTION_OK, SHELL_EXECUTION_ERROR
    
    logger_url = logging.getLogger("%s" % url)
    logger_url.setLevel(options.log_level)
    
    timeout = int(options.timeout)
    start = datetime.datetime.now()
    
    try :
        p = subprocess.Popen(shlex.split(command, posix="win" not in sys.platform), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # binaries timeout
        while p.poll() is None:
            time.sleep(0.1)
            now = datetime.datetime.now()
            if (now - start).seconds > timeout:
                logger_url.debug("Shell command PID %s reached the timeout, killing it now" % p.pid)
                logger_url.error("Screenshot somehow failed\n")
                
                if sys.platform == 'win32':
                    p.send_signal(signal.SIGTERM)
                else:
                    p.send_signal(signal.SIGKILL)
                
                return SHELL_EXECUTION_ERROR
        
        retval = p.poll()
        if retval != SHELL_EXECUTION_OK:
            if retval == PHANTOMJS_HTTP_AUTH_ERROR_CODE:
                # HTTP Authentication request
                logger_url.error("HTTP Authentication requested, try to pass credentials with -u and -b options")
            else:
                # Phantomjs general error
                logger_url.error("Shell command PID %s returned an abnormal error code: '%s'" % (p.pid,retval))
                logger_url.error("Screenshot somehow failed\n")
                    
            return SHELL_EXECUTION_ERROR
        
        else:
            logger_url.debug("Shell command PID %s ended normally" % p.pid)
            logger_url.info("Screenshot OK\n")
            return SHELL_EXECUTION_OK
    
    except OSError as e:
        if e.errno and e.errno == errno.ENOENT :
            logger_url.error('renderer binary could not have been found in your current PATH environment variable, exiting')
    
    except Exception as err:
        logger_gen.error('Unknown error: %s, exiting' % err)
        
        return SHELL_EXECUTION_ERROR

def filter_bad_filename_chars(filename):
    """
        Filter bad chars for any filename
    """
    # Before, just avoid triple underscore escape for the classic '://' pattern
    filename = filename.replace('://', '_')
    
    return re.sub('[^\w\-_\. ]', '_', filename)

def extract_all_matched_named_groups(regex, match):
    """
        Return a set of all extractable matched parameters.
        >>> full_uri_domain.groupindex
        {'domain': 1, 'port': 3}
        >>>full_uri_domain.match('http://8.8.8.8:80').group('domain')
        '8.8.8.8'
        >>>extract_all_matched_named_groups() => {'domain': '8.8.8.8', 'port': '80'}
            
    """
    result = {}
    for name, id in regex.groupindex.items():
        matched_value = match.group(name)
        if matched_value != None: result[name] = matched_value
    
    return result
    
def entry_format_validator(line):
    """
        Validate the current line against several regexes and return matched parameters (ip, domain, port etc.)
    """
    tab = { 'full_uri_domain'       : full_uri_domain,
            'fqdn_only'             : fqdn_only,
            'fqdn_and_port'         : fqdn_and_port, 
            'ipv4_and_port'         : ipv4_and_port, 
            'ipv4_only'             : ipv4_only, 
            'entry_from_csv'        : entry_from_csv }
    
    for name, regex in tab.items():
        validator = regex.match(line)
        if validator:
            return extract_all_matched_named_groups(regex, validator)

def parse_targets(options):
    """
        Parse list and convert each target to valid URI with port(protocol://foobar:port) 
    """
    
    target_list = []
    
    if options.input_file != None:    
        with open(options.input_file,'rb') as fd_input:
            try:
                lines = [l.decode('utf-8').lstrip().rstrip().strip() for l in fd_input.readlines()]
            
            except UnicodeDecodeError as e:
                logger_gen.error('Your input file is not UTF-8 encoded, please encode it before using this script')
                sys.exit(0)
    else:
        lines = [options.URL]
        
    for index, line in enumerate(lines, start=1):
        matches = entry_format_validator(line)
        
        # pass if line can be recognized as a correct input, or if no 'host' group could be found with all the regexes
        if matches == None or not('host' in matches.keys()):
            logger_gen.warn("Line %s '%s' could not have been recognized as a correct input" % (index, line))
            pass
        else:
            host = matches['host']
            
            # Protocol is 'http' by default, unless ssl is forced
            if options.ssl == True:
                protocol = 'https'
            elif 'protocol' in matches.keys():
                protocol = str(matches['protocol'])
            else:
                protocol = 'http'
            
            # Port is ('80' for http) or ('443' for https) by default, unless a specific port is supplied
            if options.port != None:
                port = options.port
            elif 'port' in matches.keys():
                port = int(matches['port'])
                
                # if port is 443, assume protocol is https if is not specified
                protocol = 'https' if port == 443 else protocol
            else:
                port = 443 if protocol == 'https' else 80
            
            # No resource URI by default
            if 'res' in matches.keys():
                res = str(matches['res'])
            else:
                res = None
            
            # perform screenshots over HTTP and HTTPS for each target
            if options.multiprotocol:
                final_uri_http_port = int(matches['port']) if 'port' in matches.keys() else 80
                final_uri_http = '%s://%s:%s' % ('http', host, final_uri_http_port)
                target_list.append(final_uri_http)
                logger_gen.info("'%s' has been formatted as '%s' with supplied overriding options" % (line, final_uri_http))
                
                
                final_uri_https_port = int(matches['port']) if 'port' in matches.keys() else 443
                final_uri_https = '%s://%s:%s' % ('https', host, final_uri_https_port)
                target_list.append(final_uri_https)
                logger_gen.info("'%s' has been formatted as '%s' with supplied overriding options" % (line, final_uri_https))
            
            else:
                final_uri = '%s://%s:%s' % (protocol, host, port)
                final_uri = final_uri + '/%s' % res if res != None else final_uri
                target_list.append(final_uri)

                logger_gen.info("'%s' has been formatted as '%s' with supplied overriding options" % (line, final_uri))
    
    return target_list

def craft_bin_path(options):
    global PHANTOMJS_BIN, CHROME_BIN, CHROMIUM_BIN, FIREFOX_BIN, XVFB_BIN
    
    final_bin = []
    
    if options.no_xserver:
        final_bin.append(XVFB_BIN)
    
    if options.renderer_binary != None: 
        final_bin.append(os.path.join(options.renderer_binary))
    
    else:
        if options.renderer == 'phantomjs':
            final_bin.append(PHANTOMJS_BIN)
        
        elif options.renderer == 'chrome':
            final_bin.append(CHROME_BIN)
        
        elif options.renderer == 'chromium':
            final_bin.append(CHROMIUM_BIN)
        
        elif options.renderer == 'firefox':
            final_bin.append(FIREFOX_BIN)
        
    return " ".join(final_bin)

def craft_arg(param):
    if "win" in sys.platform.lower():
        return '%s' % param
    else:
        return '"%s"' % param

def craft_cmd(url_and_options):
    """
        Craft the correct command with url and options
    """
    global logger_output, WEBSCREENSHOT_JS, SHELL_EXECUTION_OK, SHELL_EXECUTION_ERROR
    
    url, options = url_and_options
    
    logger_url = logging.getLogger("%s" % url)
    logger_url.addHandler(logger_output)
    logger_url.setLevel(options.log_level)

    output_filename = os.path.join(options.output_directory, ('%s.png' % filter_bad_filename_chars(url)))
        
    # PhantomJS renderer
    if options.renderer == 'phantomjs':
        # If you ever want to add some voodoo options to the phantomjs command to be executed, that's here right below
        cmd_parameters = [ craft_bin_path(options),
                           '--ignore-ssl-errors=true',
                           '--ssl-protocol=any',
                           '--ssl-ciphers=ALL' ]
        
        cmd_parameters.append("--proxy %s" % options.proxy) if options.proxy != None else None
        cmd_parameters.append("--proxy-auth %s" % options.proxy_auth) if options.proxy_auth != None else None
        cmd_parameters.append("--proxy-type %s" % options.proxy_type) if options.proxy_type != None else None

        cmd_parameters.append('%s url_capture=%s output_file=%s' % (craft_arg(WEBSCREENSHOT_JS), url, craft_arg(output_filename)))
        
        cmd_parameters.append('header="Cookie: %s"' % options.cookie.rstrip(';')) if options.cookie != None else None
        
        cmd_parameters.append('http_username=%s' % options.http_username) if options.http_username != None else None
        cmd_parameters.append('http_password=%s' % options.http_password) if options.http_password != None else None
        
        cmd_parameters.append('width=%d' % int(options.window_size.split(',')[0]))
        cmd_parameters.append('height=%d' % int(options.window_size.split(',')[1]))
        
        if options.header:
            for header in options.header:
                cmd_parameters.append('header="%s"' % header.rstrip(';'))
    
    # Chrome and chromium renderers
    elif (options.renderer == 'chrome') or (options.renderer == 'chromium'): 
        cmd_parameters =  [ craft_bin_path(options),
                            '--allow-running-insecure-content',
                            '--ignore-certificate-errors',
                            '--ignore-urlfetcher-cert-requests',
                            '--reduce-security-for-testing',
                            '--no-sandbox',
                            '--headless',
                            '--disable-gpu',
                            '--hide-scrollbars',
                            '--incognito',
                            '-screenshot=%s' % craft_arg(output_filename),
                            '--window-size=%s' % options.window_size,
                            '%s' % craft_arg(url) ]
        cmd_parameters.append('--proxy-server=%s' % options.proxy) if options.proxy != None else None
    
    # Firefox renderer
    elif options.renderer == 'firefox': 
        cmd_parameters =  [ craft_bin_path(options),
                            '--new-instance',
                            '--screenshot=%s' % craft_arg(output_filename),
                            '--window-size=%s' % options.window_size,
                            '%s' % craft_arg(url) ]
                            
    cmd = " ".join(cmd_parameters)
    
    logger_url.debug("Shell command to be executed\n'%s'\n" % cmd)
    
    execution_retval = shell_exec(url, cmd, options)
    
    return execution_retval, url

    
def take_screenshot(url_list, options):
    """
        Launch the screenshot workers
        Thanks http://noswap.com/blog/python-multiprocessing-keyboardinterrupt
    """
    global SHELL_EXECUTION_OK, SHELL_EXECUTION_ERROR
    
    screenshot_number = len(url_list)
    print("[+] %s URLs to be screenshot\n" % screenshot_number)
    
    pool = multiprocessing.Pool(processes=int(options.workers), initializer=init_worker)
    
    taken_screenshots = [r for r in pool.imap(func=craft_cmd, iterable=izip(url_list, itertools.repeat(options)))]

    screenshots_error_url = [url for retval, url in taken_screenshots if retval == SHELL_EXECUTION_ERROR]
    screenshots_error = sum(retval == SHELL_EXECUTION_ERROR for retval, url in taken_screenshots)
    screenshots_ok = int(screenshot_number - screenshots_error)
    
    print("[+] %s actual URLs screenshot" % screenshots_ok)
    print("[+] %s error(s)" % screenshots_error)
    
    if screenshots_error != 0:
        for url in screenshots_error_url:
            print("    %s" % url)

    return None
    
def main():
    """
        Dat main
    """
    global VERSION, SCREENSHOTS_DIRECTORY, LOGLEVELS
    signal.signal(signal.SIGINT, kill_em_all)
    
    #print('webscreenshot.py version %s\n' % VERSION)
    
    options = parser.parse_args()
    
    try :
        options.log_level = LOGLEVELS[options.verbosity]
        logger_gen.setLevel(options.log_level)
    except :
        parser.error("Please specify a valid log level")
        
    if (options.input_file == None) and (options.URL == None):
        parser.error('Please specify a valid input file or a valid URL')
    
    if (options.input_file != None) and (options.URL != None):
        parser.error('Please specify either an input file or an URL')
    
    if options.output_directory != None:
        options.output_directory = os.path.join(os_getcwd(), options.output_directory)
    else:
        options.output_directory = SCREENSHOTS_DIRECTORY
    
    logger_gen.debug("Options: %s\n" % options)
    if not os.path.exists(options.output_directory):
        logger_gen.info("'%s' does not exist, will then be created" % options.output_directory)
        os.makedirs(options.output_directory)
        
    url_list = parse_targets(options)
    
    take_screenshot(url_list, options)
    
    return None

if __name__ == "__main__" :
    main()
