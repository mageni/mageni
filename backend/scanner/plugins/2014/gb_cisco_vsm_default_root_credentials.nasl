###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_vsm_default_root_credentials.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Cisco Video Surveillance Manager Default Root Credentials
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

CPE = 'cpe:/a:cisco:video_surveillance_manager';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103896");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Cisco Video Surveillance Manager Default Root Credentials");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-01-28 15:02:06 +0200 (Tue, 28 Jan 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_video_surveillance_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cisco_video_surveillance_manager/installed");

  script_tag(name:"summary", value:"The remote Cisco Video Surveillance Manager is prone to a default
account authentication bypass vulnerability.");
  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
access to sensitive information or modify system configuration.");
  script_tag(name:"vuldetect", value:"Try to login with default credentials.");
  script_tag(name:"insight", value:"It was possible to login with default credentials.");
  script_tag(name:"solution", value:"Change the password.");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");
include("host_details.inc");

if( ! port = get_app_port (cpe:CPE) ) exit (0);

useragent = http_get_user_agent();
host = http_host_name( port:port );

req = 'GET /config/password.php HTTP/1.1\r\n' +
      'Host: ' +  host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n';

buf = http_send_recv (port:port, data:req + '\r\n', bodyonly:FALSE);
if( buf !~ "HTTP/1\.. 401" ) exit (0);

userpass = base64 (str:'root:secur4u');

req += 'Authorization: Basic ' + userpass + '\r\n\r\n';
buf = http_send_recv (port:port, data:req, bodyonly:FALSE);

if( "<title>Management Console Password" >< buf )
{
  report = 'It was possible to access "/config/password.php" by using the following credentials:\n\nroot:secur4u\n';
  security_message (port:port, data:report);
  exit (0);
}

exit (99);
