###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_edimax_pdts_mult_vuln_sep15.nasl 11452 2018-09-18 11:24:16Z mmartin $
#
# Edimax Products Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.806035");
  script_version("$Revision: 11452 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 13:24:16 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-09-02 15:50:18 +0530 (Wed, 02 Sep 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Edimax Products Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Edimax product(s)
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to bypass authentication or not.");

  script_tag(name:"insight", value:"Multiple flwas are due to the HTTP
  authorization is not being properly verified while sendind POST requests
  to '.cgi' and GET requests to 'FUNCTION_SCRIPT' and 'main.asp'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser, bypass
  authentication and read arbitrary files to obtain detail information about
  products.");

  script_tag(name:"affected", value:"Edimax BR6228nS/BR6228nC (Firmware version: 1.22)
  Edimax PS-1206MF (Firmware version: 4.8.25).");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38056");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38029");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("misc_func.inc");
include("http_keepalive.inc");

ediPort = get_http_port(default:80);

banner = get_http_banner( port:ediPort );
if( 'WWW-Authenticate: Basic realm=' >!< banner)exit(0);

auth = base64( str:'admin:1234' );
url = '/FUNCTION_SCRIPT';

req = http_get( item:url, port:ediPort );
buf = http_keepalive_send_recv( port:ediPort, data:req, bodyonly:FALSE );

if( "401 Unauthorized" >!< buf )exit(0);

req = http_get( item:url, port:ediPort );
req = ereg_replace( string:req, pattern:'\r\n\r\n', replace: '\r\nAuthorization: Basic ' + auth + '\r\n\r\n');

buf = http_keepalive_send_recv( port:ediPort, data:req, bodyonly:FALSE );

if(buf =~ "HTTP/1.. 200 OK" && 'MODE_="Edimax"' >< buf &&
   buf=~ 'WIRELESS_DRIVER_VERSION_="[0-9]+"' && 'MEMTYPE' >< buf)
{
  security_message(port:ediPort );
  exit(0);
}
