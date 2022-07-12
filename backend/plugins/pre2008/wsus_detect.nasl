###############################################################################
# OpenVAS Vulnerability Test
# $Id: wsus_detect.nasl 6000 2017-04-21 11:07:29Z cfi $
#
# Windows Server Update Services detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# Changes by Tenable Network Security :
# - "Services/www" check
# - Family changed to "Service detection"
# - Request fixed
#
# Copyright:
# Copyright (C) 2006 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.20377");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Windows Server Update Services detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2006 David Maciejak");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 8530);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.microsoft.com/windowsserversystem/updateservices/default.mspx");

  script_tag(name:"summary", value:"The remote host appears to be running Windows Server Update
  Services.

  Description:

  This product is used to deploy easily and quickly latest
  Microsoft product updates.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:8530 );
if( ! can_host_asp( port:port ) )
  exit( 0 );

req = http_get( item:"/Wsusadmin/Errors/BrowserSettings.aspx", port:port );
r = http_keepalive_send_recv( port:port, data:req );
if(!r)
  exit(0);

if( egrep( pattern:'<title>Windows Server Update Services error</title>.*href="/WsusAdmin/Common/Common.css"', string:r ) ||
    egrep( pattern:'<div class="CurrentNavigation">Windows Server Update Services error</div>', string:r ) ) {
  log_message( port:port );
}

exit( 0 );