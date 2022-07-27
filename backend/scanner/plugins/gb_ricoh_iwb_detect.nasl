###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ricoh_iwb_detect.nasl 12575 2018-11-29 10:41:31Z ckuersteiner $
#
# RICOH Interactive Whiteboard Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.141736");
  script_version("$Revision: 12575 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-29 11:41:31 +0100 (Thu, 29 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-29 12:16:58 +0700 (Thu, 29 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("RICOH Interactive Whiteboard Detection");

  script_tag(name:"summary", value:"Detection of RICOH Interactive Witeboard.

The script sends a connection request to the server and attempts to detect RICOH Interactive Whiteboard and to
extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("IWB/banner");

  script_xref(name:"URL", value:"https://www.ricoh-usa.com/en/products/pl/equipment/interactive-whiteboards/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/");
if ("Server: IWB Web-Server" >!< res || 'logo_product">interactive whiteboard' >!< res)
  exit(0);

# <dd>D5520</dd>
mod = eregmatch(pattern: "<dd>(D[0-9]+)</dd>", string: res);
if (!isnull(mod[1])) {
  model = mod[1];
  set_kb_item(name: "ricoh_iwb/model", value: model);
  os_cpe = 'cpe:/o:ricoh:iwb_' + tolower(model) + '_firmware';
  hw_cpe = 'cpe:/h:ricoh:iwb_' + tolower(model);
}
else {
  os_cpe = 'cpe:/o:ricoh:iwb_firmware';
  hw_cpe = 'cpe:/h:ricoh:iwb';
}

# <dd>3.1.20015.0</dd>
vers = eregmatch(pattern: "<dd>([0-9.]+)</dd>", string: res);
if (!isnull(vers[1])) {
  version = vers[1];
  os_cpe += ':' + version;
}

set_kb_item(name: "ricoh_iwb/detected", value: TRUE);

register_product(cpe: os_cpe, location: "/", port: port, service: "www");
register_product(cpe: hw_cpe, location: "/", port: port, service: "www");
register_and_report_os(os: "RICOH Interactive Whiteboard Firmware", cpe: cpe,
                       desc: "RICOH Interactive Whiteboard Detection", runs_key: "unixoide");

report = build_detection_report(app: "RICOH Interactive Whiteboard " + model + " Firmware", version: version,
                                install: "/", cpe: os_cpe, concluded: vers[0]);
report += '\n\n';
report += build_detection_report(app: "RICOH Interactive Whiteboard " + model + " Device", skip_version: TRUE,
                                 install: "/", cpe: hw_cpe);

log_message(port: port, data: report);

exit(0);
