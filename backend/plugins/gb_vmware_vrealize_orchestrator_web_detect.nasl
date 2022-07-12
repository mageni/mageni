###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_vrealize_orchestrator_web_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# VMware vRealize Orchestrator Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105864");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-12 11:45:40 +0200 (Fri, 12 Aug 2016)");
  script_name("VMware vRealize Orchestrator Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_active");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8281);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:8281 );

url = '/vco/';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>VMware vRealize Orchestrator</title>" >!< buf || "Orchestrator Control Center" >!< buf ) exit( 0 );

set_kb_item( name:"vmware/vrealize/orchestrator/installed", value:TRUE );

vers = 'unknown';
cpe = 'cpe:/a:vmware:vrealize_orchestrator';

# VMware vRealize Orchestrator 7.0.1
version = eregmatch( pattern:'<div id="appliance-info">[\n ]*VMware vRealize Orchestrator ([0-9.]+)', string: buf );

if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
  set_kb_item( name:"vmware/vrealize/orchestrator/version", value:vers );
}

register_product( cpe:cpe, location:url, port:port, service:'www' );

report = build_detection_report( app:"VMware vRealize Orchestrator", version:vers, install:url, cpe:cpe, concluded:version[0] );

log_message( port:port, data:report );
exit( 0 );

