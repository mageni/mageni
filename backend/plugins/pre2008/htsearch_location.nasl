###############################################################################
# OpenVAS Vulnerability Test
#
# ht://Dig's htsearch reveals web server path
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# changes by rd : script id
#
# Copyright:
# Copyright (C) 2000 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10385");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2000-1191");
  script_bugtraq_id(4366);
  script_name("ht://Dig's htsearch reveals web server path");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2000 SecuriTeam");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securiteam.com/exploits/htDig_reveals_web_server_configuration_paths.html");

  script_tag(name:"summary", value:"ht://Dig's htsearch CGI can be used to reveal the path location of the its configuration files.");

  script_tag(name:"impact", value:"This allows attacker to gather sensitive information about the remote host.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  VULN = FALSE;

  url = dir + "/htsearch?config=vt-test&restrict=&exclude=&method=and&format=builtin-long&sort=score&words=";
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( "ht://Dig error" >< res ) {

    if( "Unable to read configuration file '" >< res ) {

      path = eregmatch( pattern:"Unable to read configuration file '(.*)'", string:res );
      if( path ) {
        banner = "ht://Dig is exposing the local path: " + path[1];
        VULN = TRUE;
      }
    } else {

      url = dir + "/htsearch";
      req = http_get( item:url, port:port );
      res = http_keepalive_send_recv( port:port, data:req );

      # e.g. Unable to read word database file '/var/lib/htdig/db/db.words.db'
      path = eregmatch( pattern:"Unable to read (.*) file '(.*)'", string:res );
      if( path ) {
        banner = "ht://Dig is exposing the local path: " + path[2];
        VULN = TRUE;
      }
    }

    if( VULN ) {
      report = report_vuln_url( port:port, url:url ) + '\n\n' + banner;
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );