###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xenserver_web_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Citrix Xenserver Web Detection
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105763");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-14 12:25:04 +0200 (Tue, 14 Jun 2016)");
  script_name("Citrix Xenserver Web Detection");

  script_tag(name:"summary", value:"This script detects the Citrix Xenserver Webinterface");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

include("host_details.inc");

port = get_http_port( default:80 );

buf = http_get_cache( port:port, item:"/" );

if( ( "<title>Welcome to Citrix XenServer" >!< buf && buf !~ '<title>XenServer [0-9.]+</title>' ) || "XenCenter.iso" >!< buf || "Citrix Systems, Inc" >!< buf ) exit( 0 );

set_kb_item( name:"citrix_xenserver/webgui/detected", value:TRUE );

vers = 'unknown';
cpe = 'cpe:/a:citrix:xenserver';

version = eregmatch( pattern:'XenServer ([0-9.]+)', string:buf );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
}

register_product( cpe:cpe, location:"/", port:port, service:"www" );

report = build_detection_report( app:"Citrix Xenserver (Webinterface)", version:vers, install:"/", cpe:cpe, concluded:version[0] );
log_message( port:port, data:report );
exit( 0 );
