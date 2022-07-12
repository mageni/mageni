###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xerox_printer_consolidation.nasl 12940 2019-01-04 09:23:20Z ckuersteiner $
#
# Xerox Printer Detection Consolidation
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141824");
  script_version("$Revision: 12940 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-04 10:23:20 +0100 (Fri, 04 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-04 13:08:39 +0700 (Fri, 04 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Xerox Printer Detection Consolidation");

  script_tag(name:"summary", value:"Reports the Xerox Printer model and firmware version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_xerox_printer_detect.nasl", "gb_xerox_printer_snmp_detect.nasl");
  script_mandatory_keys("xerox_printer/detected");

  script_xref(name:"URL", value:"https://www.xerox.com/en-us/printing-equipment");

  exit(0);
}

include("host_details.inc");
include("xerox_printers.inc");

if (!get_kb_item("xerox_printer/detected"))
  exit(0);

detected_model = "unknown";
detected_fw_version = "unknown";

foreach source (make_list("http", "snmp")) {
  fw_version_list = get_kb_list("xerox_printer/" + source + "/*/fw_version");
  foreach fw_version (fw_version_list) {
    if (fw_version && detected_fw_version == "unknown") {
      detected_fw_version = fw_version;
      set_kb_item(name: "xerox_printer/fw_version", value: fw_version);
    }
  }

  model_list = get_kb_list("xerox_printer/" + source + "/*/model");
  foreach model (model_list) {
    if (model && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "xerox_printer/model", value: model);
    }
  }
}

app_name = "Xerox Printer ";
if (detected_model != "unknown") {
  app_name += detected_model;
  # TODO: separate for app, os and hw cpe
  cpe = build_xerox_cpe(model:model);
}

if (detected_fw_version != "unknown")
  cpe += ':' + detected_fw_version;

location = "/";

if (http_ports = get_kb_list("xerox_printer/http/port")) {
  foreach port (http_ports) {
    concluded = get_kb_item("xerox_printer/http/" + port + "/concluded");
    concUrl = get_kb_item("xerox_printer/http/" + port + "/concludedUrl");

    extra += "HTTP(s) on port " + port + '/tcp\n';
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';
    if (concUrl)
      extra += '  Concluded from version/product identification location: ' + concUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("xerox_printer/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    concluded = get_kb_item('xerox_printer/snmp/' + port + '/concluded');
    if (concluded)
      extra += '  Concluded from SNMP SysDesc: ' + concluded + '\n';

    register_product(cpe: cpe, location: port + 'udp', port: port, service: "snmp", proto: "udp");
  }
}

report += build_detection_report(app: app_name, version: detected_fw_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

pref = get_kb_item("global_settings/exclude_printers");
if (pref == "yes") {
  log_message(port: 0, data: 'The remote host is a printer. The scan has been disabled against this host.\n' +
                             'If you want to scan the remote host, uncheck the "Exclude printers from scan" ' +
                             'option and re-scan it.');
  set_kb_item(name:"Host/dead", value:TRUE);
}

exit(0);
