###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmturbo_operations_manager_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# VMTurbo Operations Manager Detection
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105066");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-08-18 13:58:41 +0200 (Mon, 18 Aug 2014)");
  script_name("VMTurbo Operations Manager Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts
to extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");

include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

url = '/cgi-bin/vmtadmin.cgi?callType=ACTION&actionType=VERSIONS';
req = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req );
if( buf == NULL ) continue;

if( "vmtbuild:" >< buf && "vmtrelease:" >< buf )
{
  install = url;
  vers = "unknown";
  version = eregmatch( string: buf, pattern: "vmtrelease:([^,]+)",icase:TRUE );

  if ( ! isnull( version[1] ) ) vers = version[1];
  set_kb_item(name:"vmturbo/installed",value:TRUE);

  build = eregmatch( string: buf, pattern: "vmtbuild:([^,]+)",icase:TRUE );
  if ( ! isnull( build[1] ) )
  {
    buildNR = build[1];
    set_kb_item(name:"vmturbo/" + port + "/build",value:buildNR);
  }

  cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:vmturbo:operations_manager:" );
  if( isnull( cpe ) ) cpe = "cpe:/a:vmturbo:operations_manager";

  register_product( cpe:cpe, location:install, port:port );

  log_message( data: build_detection_report( app:"VMTurbo Operations Manager",
                                             version:vers + ' Build: ' + buildNR,
                                             install:install,
                                             cpe:cpe,
                                             concluded: version[0] ),
               port:port );
}

exit(0);
