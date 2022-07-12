###############################################################################
# OpenVAS Vulnerability Test
#
# Mailman private.py Directory Traversal Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2005 George A. Theall
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

CPE = "cpe:/a:gnu:mailman";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16339");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2005-0202");
  script_bugtraq_id(12504);

  script_name("Mailman private.py Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2005 George A. Theall");
  script_dependencies("mailman_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("gnu_mailman/detected");

  script_xref(name:"URL", value:"http://mail.python.org/pipermail/mailman-announce/2005-February/000076.html");
  script_xref(name:"URL", value:"http://lists.netsys.com/pipermail/full-disclosure/2005-February/031562.html");

  script_tag(name:"summary", value:"Authenticated Mailman users can view arbitrary files on the remote host.

  According to its version number, the remote installation of Mailman reportedly is prone to a directory traversal
  vulnerability in 'Cgi/private.py'.");

  script_tag(name:"insight", value:"The flaw comes into play only on web servers that
  don't strip extraneous slashes from URLs, such as Apache 1.3.x, and
  allows a list subscriber, using a specially crafted web request, to
  retrieve arbitrary files from the server - any file accessible by the
  user under which the web server operates, including email addresses
  and passwords of subscribers of any lists hosted on the server.  For
  example, if '$user' and '$pass' identify a subscriber of the list
  '$listname@$target', then the following URL :

  http://example.com/mailman/private/$listname/.../....///mailman?username=$user&password=$pass

  allows access to archives for the mailing list named 'mailman' for
  which the user might not otherwise be entitled.");

  script_tag(name:"solution", value:"Upgrade to Mailman 2.1.6b1 or apply the fix referenced in the first
  URL above.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");
include("global_settings.inc");

# Web servers to ignore because it's known they strip extra slashes from URLs.
# nb: these can be regex patterns.
web_servers_to_ignore = make_list(
  "Apache(-AdvancedExtranetServer)?/2",                      # Apache 2.x
  'Apache.*/.* \\(Darwin\\)'
);

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

# Skip check if the server's type and version indicate it's not a problem
banner = get_http_banner( port:port );
if( banner ) {
  web_server = strstr( banner, "Server:" );
  if( web_server ) {
    web_server = web_server - "Server: ";
    web_server = web_server - strstr( web_server, '\r' );
    foreach pat( web_servers_to_ignore ) {
      if( ereg( string:web_server, pattern:pat ) ) {
        debug_print( "skipping because web server claims to be '", web_server, "'." );
        exit( 0 );
      }
    }
  }
}

if( ! info = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
vers = info['version'];
path = info['location'];

if( vers =~ "^2\.(0.*|1($|[^0-9.]|\.[1-5]($|[^0-9])))" ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.1.6b1", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
