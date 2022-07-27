###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_intelbras_ncloud_devices_http_detect.nasl 12572 2018-11-29 09:40:42Z cfischer $
#
# Intelbras NCLOUD Devices Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.108491");
  script_version("$Revision: 12572 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-29 10:40:42 +0100 (Thu, 29 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-29 09:14:30 +0100 (Thu, 29 Nov 2018)");
  script_name("D-Link DAP Devices Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("GoAhead-Webs/banner");

  script_xref(name:"URL", value:"http://en.intelbras.com.br");

  script_tag(name:"summary", value:"Detection of Intelbras NCLOUD devices.

  The script sends a connection request to the server and attempts to
  determine if the remote host is a Intelbras NCLOUD device from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:8080 );
if( ! can_host_asp( port:port ) )
  exit( 0 );

buf = http_get_cache( item:"/login.asp", port:port );

if( buf =~ "^HTTP/1\.[01] 200" && buf =~ "<title>Roteador NCLOUD" && "nbox/logo.png" >< buf ) {

  set_kb_item( name:"intelbras/ncloud/detected", value:TRUE );
  set_kb_item( name:"intelbras/ncloud/www/detected", value:TRUE );

  fw_version = "unknown";
  os_app     = "Intelbras NCLOUD ";
  os_cpe     = "cpe:/o:intelbras:ncloud_";
  hw_version = "unknown";
  hw_app     = "Intelbras NCLOUD ";
  hw_cpe     = "cpe:/h:intelbras:ncloud_";
  model      = "unknown";
  install    = "/";

  # <title>Roteador NCLOUD 300</title>
  mo = eregmatch( pattern:"<title>Roteador NCLOUD ([0-9]+)", string:buf );
  if( mo[1] ) {
    model = mo[1];
    os_app += model + " Firmware";
    os_cpe += model + "_firmware";
    hw_app += model + " Device";
    hw_cpe += model;
    set_kb_item( name:"intelbras/ncloud/model", value:model );
  } else {
    os_app += "Unknown Model Firmware";
    os_cpe += "unknown_model_firmware";
    hw_app += " Unknown Model Device";
    hw_cpe += "unknown_model";
  }

  register_and_report_os( os:os_app, cpe:os_cpe, banner_type:"Intelbras NCLOUD Device Login Page", port:port, desc:"Intelbras NCLOUD Devices Detection", runs_key:"unixoide" );
  register_product( cpe:os_cpe, location:install, port:port, service:"www" );
  register_product( cpe:hw_cpe, location:install, port:port, service:"www" );

  report = build_detection_report( app:os_app,
                                   version:fw_version,
                                   concluded:mo[0],
                                   install:install,
                                   cpe:os_cpe );

  report += '\n\n' + build_detection_report( app:hw_app,
                                             skip_version:TRUE,
                                             install:install,
                                             cpe:hw_cpe );

  log_message( port:port, data:report );
}

exit( 0 );