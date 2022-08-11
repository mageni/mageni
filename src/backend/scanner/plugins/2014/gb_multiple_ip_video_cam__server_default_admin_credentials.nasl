###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_multiple_ip_video_cam__server_default_admin_credentials.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Multiple IP Video/Camera Server Web Interface Default Admin Credentials
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103887");
  script_version("$Revision: 11867 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Multiple IP Video/Camera Server Web Interface Default Admin Credentials");
  script_xref(name:"URL", value:"http://dariusfreamon.wordpress.com/2014/01/18/s3-s2071-s4071-ip-video-server-web-interface-default-admin-credentials/");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-21 15:02:06 +0200 (Tue, 21 Jan 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("httpd/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"The remote IP Video/Camera server web interface is prone to a default
account authentication bypass vulnerability.");
  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
access to sensitive information or modify system configuration.");
  script_tag(name:"vuldetect", value:"Try to login with default credentials.");
  script_tag(name:"insight", value:"It was possible to login with default credentials.");
  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");

port = get_http_port( default:80 );
banner = get_http_banner( port:port );

if( "Server: httpd" >!< banner || banner !~ "HTTP/1\.. 401" ) exit (0);

if ( "ip camera" >!< tolower ( banner ) &&
     "IP SPEED DOME" >!< banner &&
     "IP Video Server" >!< tolower( banner )
  ) exit (0);

credentials = make_list("3sadmin:27988303","root:root");

host = http_host_name( port:port );

foreach credential ( credentials )
{
  userpass = base64( str:credential );
  req = 'GET / HTTP/1.1\r\n' +
        'Host: ' +  host + '\r\n' +
        'Authorization: Basic ' + userpass + '\r\n' +
        '\r\n';

  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );
  if( buf =~ "HTTP/1\.. 200" )
    defaults = defaults + credential + '\n';

}

if( defaults )
{
  defaults = str_replace( string:defaults, find:":", replace:"/" );
  report = 'It was possible to login using the following credentials:\n\n' + defaults;
  security_message( port:port, data:report );
  exit (0);
}

exit (99);
