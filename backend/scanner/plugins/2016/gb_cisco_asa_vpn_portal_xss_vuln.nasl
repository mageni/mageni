###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_asa_vpn_portal_xss_vuln.nasl 11841 2018-10-11 12:32:25Z cfischer $
#
# Cisco ASA Software VPN Portal Cross-Site Scripting (XSS) Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:cisco:asa";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806687");
  script_version("$Revision: 11841 $");
  script_cve_id("CVE-2014-2120");
  script_bugtraq_id(66290);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-11 14:32:25 +0200 (Thu, 11 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-02-22 13:34:22 +0530 (Mon, 22 Feb 2016)");
  script_name("Cisco ASA Software VPN Portal Cross-Site Scripting (XSS) Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("cisco_asa/webvpn/installed");

  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCun19025");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=33406");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/135813");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Feb/82");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66290");
  script_xref(name:"URL", value:"https://www.trustwave.com/Resources/SpiderLabs-Blog/CVE-2014-2120-%E2%80%93-A-Tale-of-Cisco-ASA-%E2%80%9CZero-Day%E2%80%9D/");
  script_xref(name:"URL", value:"https://www3.trustwave.com/spiderlabs/advisories/TWSL2014-008.txt");

  script_tag(name:"summary", value:"This host is running Cisco ASA SSL VPN and
  is prone to cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"The flaw is due to an an error in password
  recovery form which fails to filter properly the hidden inputs.

  NOTE: The vulnerability was verified on Internet Explorer 6.0 (more modern browsers are unaffected).");

  script_tag(name:"impact", value:"Successful exploitation allow the attacker
  to execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"Cisco ASA Software versions 8.4(7) and prior and 9.1(4) and prior are vulnerable.");

  script_tag(name:"solution", value:"Updates are available, please see the references for more information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

prestr  = rand_str( length:6, charset:"abcdefghijklmnopqrstuvwxyz0123456789" );
poststr = rand_str( length:11, charset:"abcdefghijklmnopqrstuvwxyz0123456789" );

url = dir + "/+CSCOE+/logon.html?reason=2&a0=63&a1=&a2=&a3=0&next=&auth_handle=" + prestr +
            '"%20style%3dbehavior%3aurl(%23default%23time2)%20onbegin%3dalert(1)%20' + poststr +
            "&status=0&username=&password_min=0&state=&tgroup=&serverType=0&password_days=0";

# Unpatched versions are returning:
# <input type=hidden name=auth_handle    value="0712b0\" style=behavior:url(#default#time2) onbegin=alert(1) 09094cf0a35">
# Patched versions are returning:
# <input type=hidden name=auth_handle    value="39325z&quot; style=behavior:url(#default#time2) onbegin=alert(1) envhdgoxffc">

check_pattern = '<input type=hidden name=auth_handle\\s+value="' + prestr + '\\\\" style=behavior:url\\(#default#time2\\) onbegin=alert\\(1\\) ' + poststr + '">';

if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:check_pattern, extra_check:make_list( ">New Password<", ">SSL VPN Service<" ) ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
