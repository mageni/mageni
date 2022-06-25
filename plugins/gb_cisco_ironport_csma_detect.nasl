###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ironport_csma_detect.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Cisco IronPort Content Security Management Appliance Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803753");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-09-03 18:58:59 +0530 (Tue, 03 Sep 2013)");
  script_name("Cisco IronPort Content Security Management Appliance Web Interface Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

csmaPort = get_http_port(default:443);
useragent = http_get_user_agent();
csmahost = http_host_name(port:csmaPort);

csmaReq = string("GET /login HTTP/1.1\r\n",
             "Host: ", csmahost, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Cookie: sid=", rand(),"\r\n\r\n");
csmaRes = http_keepalive_send_recv(port:csmaPort, data:csmaReq);

if( ( "<title>Cisco IronPort" >!< csmaRes && "SecurityManagementApp" >!< csmaRes) &&
    csmaRes !~ "<title>\s*Cisco\s*Content Security Management( Virtual)? Appliance" ){
  exit(0);
}

if( "Set-Cookie" >< csmaRes )
{
  cookie = eregmatch( pattern:'Set-Cookie: ([^\r\n]+)', string:csmaRes );
  if( ! isnull( cookie[1] ) ) set_kb_item( name:"cisco_csm/http/cookie", value:cookie[1] );
}

set_kb_item( name:"cisco_csm/installed", value:TRUE );
set_kb_item( name:"cisco_csm/http/port", value:csmaPort );

csmaVersion = eregmatch(string: csmaRes, pattern: "v(([0-9.]+)-?[0-9]+)");
if( isnull( csmaVersion[1] ) )
  csmaVersion = eregmatch( pattern:'Version: (([0-9.]+)-?[0-9]+)', string:csmaRes );

cpe = "cpe:/h:cisco:content_security_management_appliance";

version = 'unknown';

if( ! isnull( csmaVersion[1] ) )
{
  version = csmaVersion[1];
  cpe += ':' + version;
  set_kb_item( name:"cisco_csm/version/http", value:version );
}

model = eregmatch( pattern:'ext_login_model">Cisco ([^<]+)<', string: csmaRes);

if( ! isnull( model[1] ) )
{
  model = model[1];
  set_kb_item( name:"cisco_csm/model/http", value:model );
}

log_message(data: build_detection_report(app:"Cisco Content Security Management Appliance Web Interface",
                                         version:version,
                                         install:'/',
                                         cpe:cpe,
                                         concluded: csmaVersion[0]),
                                         port:csmaPort);
exit( 0 );

