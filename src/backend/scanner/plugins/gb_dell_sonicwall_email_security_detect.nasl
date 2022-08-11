###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_sonicwall_email_security_detect.nasl 13688 2019-02-15 10:21:10Z cfischer $
#
# Dell SonicWall EMail Security Detection
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103929");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_version("$Revision: 13688 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 11:21:10 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-03-28 12:48:51 +0100 (Fri, 28 Mar 2014)");
  script_name("Dell SonicWall EMail Security Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("http_version.nasl", "smtpserver_detect.nasl");
  script_require_ports("Services/www", 80, "Services/smtp", 25, 465, 587);

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts
  to extract the version number from the reply.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("smtp_func.inc");
include("cpe.inc");
include("host_details.inc");

global_var ar;

function _report( version, port, service )
{
  if( isnull( version ) || isnull( port ) ) exit( 0 );

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:sonicwall:email_security:");
  if( isnull( cpe ) )
    cpe = 'cpe:/a:sonicwall:email_security';

  if( ! ar )
  {
    register_product(cpe:cpe, location:port + "/tcp", port:port, service:service);
    set_kb_item(name: "sonicwall_email_security/port", value: port);
    ar = TRUE;
  }

  log_message(data: build_detection_report(app:"SonicWALL Email Security",
                                           version:version,
                                           install:port + '/tcp',
                                           cpe:cpe,
                                           concluded: 'Remote Banner'),
              port:port);
}

smtp_ports = smtp_get_ports();
foreach smtp_port ( smtp_ports )
{
  smtp_banner = get_smtp_banner( port:smtp_port );
  if( smtp_banner =~ "220.*SonicWALL" )
  {
    version = eregmatch( pattern:"SonicWALL \(([^)]+)\)", string:smtp_banner );
    if( ! isnull( version[1] ) )
      _report( version:version[1], port:smtp_port, service:"smtp" );
    else
      _report( version:'unknown', port:smtp_port, service:"smtp" );
  }
}

http_port = get_http_port(default:80);
buf = http_get_cache(item:"/login.html", port:http_port);

if( "<title>Login</title>" >< buf && ">Email Security" >< buf && "Dell" >< buf )
{
  set_kb_item(name: "sonicwall_email_security/www/port", value: http_port);
  version = eregmatch( pattern:'id="firmwareVersion" value="([^"]+)"', string: buf);
  if( ! isnull( version[1] ) )
  {
    _report( version:version[1], port:http_port, service:"www" );
  } else {
    version = eregmatch( pattern:'<div class="lefthand">([^<]+)</div>', string: buf);
    if( ! isnull( version[1] ) )
      _report( version:version[1], port:http_port, service:"www" );
    else
      _report( version:'unknown', port:http_port, service:"www" );

  }
}

exit( 0 );