###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dap_detect.nasl 12266 2018-11-08 16:05:51Z cfischer $
#
# D-Link DAP Devices Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810234");
  script_version("$Revision: 12266 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-08 17:05:51 +0100 (Thu, 08 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-12-09 15:22:03 +0530 (Fri, 09 Dec 2016)");
  script_name("D-Link DAP Devices Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of D-Link DAP Devices.

  The script sends a connection request to the server and attempts to
  determine if the remote host is a D-Link DAP device from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );
buf = http_get_cache( item:"/", port:port );

if( ( buf =~ 'Product Page:.*>DAP' || 'Product Page :.*>DAP' ) &&
    ( buf =~ ">Copyright.*D-Link Systems, Inc" || ( "<title>D-LINK SYSTEMS, INC. | WIRELESS AP : LOGIN</title>" >< buf ) ) ) {

  set_kb_item( name:"Host/is_dlink_dap_device", value:TRUE );
  set_kb_item( name:"Host/is_dlink_device", value:TRUE );

  fw_version = "unknown";
  os_app     = "D-Link DAP";
  os_cpe     = "cpe:/o:d-link:dap";
  hw_version = "unknown";
  hw_app     = "D-Link DAP";
  hw_cpe     = "cpe:/h:d-link:dap";
  model      = "unknown";
  install    = "/";

  mo = eregmatch( pattern:'>DAP-([0-9.]+)', string:buf );
  if( mo[1] ) {
    model = mo[1];
    os_app += "-" + model + " Firmware";
    os_cpe += "-" + model + "_firmware";
    hw_app += "-" + model + " Device";
    hw_cpe += "-" + model;
    set_kb_item( name:"d-link/dap/model", value:model );
  } else {
    os_app += " Unknown Model Firmware";
    os_cpe += "-unknown_model_firmware";
    hw_app += " Unknown Model Device";
    hw_cpe += "-unknown_model";
  }

  # <td align="right" nowrap>Hardware Version: A1 &nbsp;&nbsp;&nbsp;Firmware Version: 1.13</td>
  fw_ver = eregmatch( pattern:'Firmware Version ?: V?([0-9.]+)', string:buf );
  if( fw_ver[1] ) {
    os_cpe    += ":" + fw_ver[1];
    fw_version = fw_ver[1];
    set_kb_item( name:"d-link/dap/fw_version", value:fw_version );
  }

  # <td align="right" nowrap>Hardware Version: A1 &nbsp;&nbsp;&nbsp;Firmware Version: 1.13</td>
  hw_ver = eregmatch( pattern:'>Hardware Version ?: ([0-9A-Za-z.]+)', string:buf );
  if( hw_ver[1] ) {
    hw_cpe    += ":" + tolower( hw_ver[1] );
    hw_version = hw_ver[1];
    set_kb_item( name:"d-link/dap/hw_version", value:hw_version );
  }

  register_and_report_os( os:os_app, cpe:os_cpe, banner_type:"D-Link DAP Device Login Page", port:port, desc:"D-Link DAP Devices Detection", runs_key:"unixoide" );
  register_product( cpe:os_cpe, location:install, port:port, service:"www" );
  register_product( cpe:hw_cpe, location:install, port:port, service:"www" );

  report = build_detection_report( app:os_app,
                                   version:fw_version,
                                   concluded:fw_ver[0],
                                   install:install,
                                   cpe:os_cpe );

  report += '\n\n' + build_detection_report( app:hw_app,
                                             version:hw_version,
                                             concluded:hw_ver[0],
                                             install:install,
                                             cpe:hw_cpe );

  log_message( port:port, data:report );
}

exit( 0 );