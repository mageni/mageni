###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_brother_hl_series_printer_detect.nasl 11408 2018-09-15 11:35:21Z cfischer $
#
# Brother HL Series Printers Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.813390");
  script_version("$Revision: 11408 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:35:21 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-06-06 15:18:41 +0530 (Wed, 06 Jun 2018)");
  script_name("Brother HL Series Printers Detection");

  script_tag(name:"summary", value:"Detection of Brother HL Series Printers.

  The script sends a connection request to the remote host and
  attempts to detect if the remote host is a Brother HL Series printer.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  # nb: Don't use http_version.nasl as the Detection should run as early
  # as possible if the printer should be marked dead as requested.
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

brPort = get_http_port(default:80);

res = http_get_cache(item:"/general/information.html?kind=item", port:brPort);

# If updating here please also update the check in dont_print_on_printers.nasl
if(res =~ "<title>Brother HL.*series</title>" && res =~ "Copyright.*Brother Industries")
{
  version = "unknown";
  model = "unknown";

  set_kb_item( name:"Brother/HL/Printer/installed", value:TRUE );

  model = eregmatch(pattern:'modelName"><h1>([0-9A-Z-]+) series</h1>', string:res);
  ver = eregmatch(pattern:"Firmware&#32;Version</dt><dd>([0-9.]+)</dd>", string:res);

  if(model[1])
  {
    model = model[1];
    set_kb_item(name:"Brother/HL/Printer/model", value:model);
  }
  if(ver[1])
  {
    version = ver[1];
    set_kb_item(name:"Brother/HL/Printer/version", value:version);
  }

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base: "cpe:/h:brother:" + tolower(model) + ":");
  if(!cpe)
    cpe = 'cpe:/h:brother:' + tolower(model);

  register_product( cpe:cpe, port:brPort, location:"/");
  log_message( data:build_detection_report( app:"Brother HL series printer",
                                            version:version,
                                            install:"/",
                                            cpe:cpe,
                                            concluded:model + " Firmware " + version),
                                            port:brPort );
  pref = get_kb_item( "global_settings/exclude_printers" );
  if( pref == "yes" ) {
    log_message( port:brPort, data:'The remote host is a printer. The scan has been disabled against this host.\nIf you want to scan the remote host, uncheck the "Exclude printers from scan" option and re-scan it.' );
    set_kb_item( name:"Host/dead", value:TRUE );
  }
  exit(0);
}
exit(0);
