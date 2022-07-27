###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_laser_printer_detect.nasl 11508 2018-09-20 13:44:58Z cfischer $
#
# Dell Laser Multi Function Printer(MFP) Printers Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.814217");
  script_version("$Revision: 11508 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-20 15:44:58 +0200 (Thu, 20 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-19 14:33:52 +0530 (Wed, 19 Sep 2018)");
  script_name("Dell Laser Multi Function Printer(MFP) Printers Detection");

  script_tag(name:"summary", value:"Detection of Dell Laser MFP Printer.

  The script sends a connection request to the remote host and attempts to
  detect if the remote host is a Dell Laser MFP Printer.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_xref(name:"URL", value:"https://www.dell.com");
  script_family("Product detection");
  # nb: Don't use http_version.nasl as the Detection should run as early
  # as possible if the printer should be marked dead as requested.
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

dellPort = get_http_port(default:80);

res = http_get_cache(item:"/default.html", port:dellPort);
if(res =~ "<TITLE>Dell Laser MFP.*</TITLE>" && "prn_status.htm" >< res)
{
  set_kb_item( name:"Dell/Laser/MFP/Printer/Running", value:TRUE );
  set_kb_item( name:"target_is_printer", value:TRUE );
  set_kb_item( name:"Dell_Printer/Port", value:dellPort);
  printer_model = eregmatch(pattern:'Dell Laser MFP ([0-9A-Za-z]+)<', string:res);

  if(printer_model[1])
  {
    model = printer_model[1];
    set_kb_item( name:"Dell_Printer_Model", value:model);
    cpe_printer_model = tolower( model);

    cpe = "cpe:/h:dell:" + cpe_printer_model;
    cpe = str_replace(string:cpe, find:" ", replace:"_" );
  }

  if(!model)
  {
    model = "Unknown Dell model";
    cpe = "cpe:/h:dell:unknown_model";
  }

  url = "/printer_info.htm";
  res = http_get_cache(item:url, port:dellPort);
  firm_ver = eregmatch( pattern:">Printer Firmware Version.*>([0-9.]+)<.*Engine Firmware Version", string:res);
  if( firm_ver[1]) {
    set_kb_item( name:"dell_mfp_printer/firmware_ver", value:firm_ver[1] );
    cpe = cpe + ":" + firm_ver[1];
  }

  register_product( cpe:cpe, location:dellPort + "/tcp", port:dellPort );
  log_message(data:build_detection_report(app:"Dell Laser MFP " + model + " Printer Device",
                                            version: firm_ver[1],
                                            install:dellPort + "/tcp",
                                            cpe:cpe,
                                            concluded:printer_model[0]));

  pref = get_kb_item( "global_settings/exclude_printers" );
  if( pref == "yes" ) {
    log_message( port:dellPort, data:'The remote host is a printer. The scan has been disabled against this host.\nIf you want to scan the remote host, uncheck the "Exclude printers from scan" option and re-scan it.');
    set_kb_item( name:"Host/dead", value:TRUE );
  }
}

exit( 0 );