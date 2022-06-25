###############################################################################
# OpenVAS Vulnerability Test
# $Id: imp_detect.nasl 12016 2018-10-22 12:50:10Z cfischer $
#
# Horde IMP Detection
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12643");
  script_version("$Revision: 12016 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 14:50:10 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Horde IMP Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 George A. Theall");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.horde.org/imp/");

  script_tag(name:"summary", value:"This script detects whether the remote host is running Horde IMP
  and extracts version numbers and locations of any instances found.

  IMP is a PHP-based webmail package from The Horde Project that provides
  access to mail accounts via POP3 or IMAP.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

check_files = make_array(
  "/services/help/?module=imp&show=about", ">This is Imp .{0,3}\(?([0-9.]+)\)?\.<", # nb: version 4.x, e.g. <h2 align="center">This is Imp H3 (4.1.3).</h2>
  "/docs/CHANGES", "^ *v([0-9.]+) *-?(RC[0-9]|BETA|cvs)$", # nb: version 3.x+, e.g. v4.1.3-cvs or v4.1-RC2 v4.0-BETA
  "/test.php", "^ *<li>IMP: +([0-9.]+) *</li> *$", # nb: test.php available is itself a vulnerability but sometimes available
  "/README", "^Version +([0-9.]+) *$", # nb: README is not guaranteed to be either available or accurate!!!
  "/lib/version.phps", "IMP_VERSION', '([0-9.]+)'", # nb: another security risk -- ability to view PHP source.
  "/status.php3", ">IMP, Version ([0-9.]+)<"); # nb: version 2.x

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

# nb: Directories beyond cgi_dirs() come from a Google search - 'intitle:"welcome to" horde' - and represent the more popular installation paths currently.
foreach dir( make_list_unique( "/webmail", "/horde", "/horde/imp", "/email", "/imp", "/mail", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/";
  res = http_get_cache( port:port, item:url );

  if( res && res =~ "^HTTP/1\.[01] 200" &&
      ( "<!-- IMP: Copyright 200" >< res ||
        "document.imp_login.imapuser.value" >< res ||
        "document.imp_login.loginButton.disabled" >< res ||
        "IMP: http://horde.org/imp/" >< res
      ) ) {

    set_kb_item( name:"horde/imp/detected", value:TRUE );
    version  = "unknown";
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

    foreach check_file( keys( check_files ) ) {

      pattern = check_files[check_file];

      url = dir + check_file;

      res = http_get_cache( item:url, port:port );

      if( res =~ "^HTTP/1\.[01] 200" && match = egrep( pattern:pattern, string:res, icase:FALSE ) ) {
        if( "/docs/CHANGES" >< url ) {
          foreach _match( split( match ) ) {
            _match = chomp( _match );
            vers = eregmatch( pattern:pattern, string:_match );
            if( vers[1] )
              break;
          }
        } else {
          vers = eregmatch( pattern:pattern, string:match );
        }

        if( vers[1] ) {
          conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
          version = vers[1];
          break;
        }
      }
    }
    register_and_report_cpe( app:"Horde IMP", ver:version, concluded:vers[0], conclUrl:conclUrl, base:"cpe:/a:horde:imp:", expr:"^([0-9.]+)", insloc:install, regPort:port );
  }
}

exit( 0 );
