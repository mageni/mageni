# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142078");
  script_version("$Revision: 14052 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 10:57:15 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-06 12:29:16 +0700 (Wed, 06 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Drobo NAS Consolidation");

  script_tag(name:"summary", value:"Reports the Drobo NAS model and firmware version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_droboaccess_detect.nasl", "gb_drobomysql_detect.nasl", "gb_drobo_nasd_detect.nasl",
                      "gb_drobopix_detect.nasl");
  script_mandatory_keys("drobo/nas/detected");

  script_xref(name:"URL", value:"https://www.drobo.com/storage-products/");

  exit(0);
}

include("host_details.inc");

if (!get_kb_item("drobo/nas/detected"))
  exit(0);

detected_version = "unknown";
detected_model = "";
detected_esaid = "";

foreach source (make_list("nasd", "mysqlapp", "drobopix")) {
  fw_version_list = get_kb_list("drobo/" + source + "/fw_version");
  foreach fw_version (fw_version_list) {
    if (fw_version && detected_version == "unknown") {
      detected_version = fw_version;
      set_kb_item(name: "drobo/nas/version", value: fw_version);
    }
  }

  model_list= get_kb_list("drobo/" + source + "/model");
  foreach model (model_list) {
    if (model && detected_model == "") {
      detected_model = model;
      set_kb_item(name: "drobo/nas/model", value: detected_model);
    }
  }

  if (detected_esaid == "") {
    esaid_list = get_kb_list("drobo/" + source + "/esaid");
    foreach esaid (esaid_list) {
      detected_esaid = esaid;
      set_kb_item(name: "drobo/nas/esaid", value: detected_esaid);
      break;
    }
  }
}

app_name = "Drobo NAS ";
if (detected_model != "") {
  app_name += detected_model;
  mod = eregmatch(pattern: 'Drobo ([0-9A-Z]+)', string: detected_model);
  if (!isnull(mod[1])) {
    app_cpe = 'cpe:/a:drobo:' + tolower(mod[1]);
    os_cpe = 'cpe:/o:drobo:' + tolower(mod[1]) + '_firmware';
    hw_cpe = 'cpe:/h:drobo:' + tolower(mod[1]);
  } else {
    app_cpe = 'cpe:/a:drobo:nas';
    os_cpe = 'cpe:/o:drobo:nas_firmware';
    hw_cpe = 'cpe:/h:drobo:nas';
  }
}
else {
  app_cpe = 'cpe:/a:drobo:nas';
  os_cpe = 'cpe:/o:drobo:nas_firmware';
  hw_cpe = 'cpe:/h:drobo:nas';
}

if (detected_version != "unknown") {
  app_cpe += ':' + detected_version;
  os_cpe += ':' + detected_version;
}

register_and_report_os(os: "Drobo NAS Firmware", cpe: os_cpe, desc: "Drobo NAS Consolidation",
                       runs_key: "unixoide");

if (get_kb_item("drobo/droboaccess/detected")) {
  extra += 'Drobo DroboAccess:\n';
  if (draccss_ports = get_kb_list("drobo/droboaccess/port")) {
    foreach port (draccss_ports) {
      extra += "  HTTP(s) on port " + port + '/tcp\n';

      register_product(cpe: hw_cpe, location: "/", port: port, service: "www");
      register_product(cpe: os_cpe, location: "/", port: port, service: "www");
      register_product(cpe: app_cpe, location: "/", port: port, service: "www");
    }
  }
}

if (get_kb_item("drobo/drobopix/detected")) {
  extra += 'Drobo DroboPix:\n';
  if (drpix_ports = get_kb_list("drobo/drobopix/port")) {
    foreach port (drpix_ports) {
      extra += "  HTTP(s) on port " + port + '/tcp\n';

      register_product(cpe: hw_cpe, location: "/", port: port, service: "www");
      register_product(cpe: os_cpe, location: "/", port: port, service: "www");
      register_product(cpe: app_cpe, location: "/", port: port, service: "www");
    }
  }
}

if (get_kb_item("drobo/mysqlapp/detected")) {
  extra += 'Drobo MySQL App:\n';
  if (draccss_ports = get_kb_list("drobo/mysqlapp/port")) {
    foreach port (draccss_ports) {
      extra += "  HTTP(s) on port " + port + '/tcp\n';

      register_product(cpe: hw_cpe, location: "/", port: port, service: "www");
      register_product(cpe: os_cpe, location: "/", port: port, service: "www");
      register_product(cpe: app_cpe, location: "/", port: port, service: "www");
    }
  }
}

if (get_kb_item("drobo/nasd/detected")) {
  extra += 'Drobo NASD:\n';
  if (draccss_ports = get_kb_list("drobo/nasd/port")) {
    foreach port (draccss_ports) {
      extra += "  NASd on port " + port + '/tcp\n';

      register_product(cpe: hw_cpe, location: port + "/tcp", port: port, service: "drobo-nasd");
      register_product(cpe: os_cpe, location: port + "/tcp", port: port, service: "drobo-nasd");
      register_product(cpe: app_cpe, location: port + "/tcp", port: port, service: "drobo-nasd");
    }
  }
}

report = build_detection_report(app: app_name + " Firmware", version: detected_version, install: "/", cpe: os_cpe);

report += '\n\n';
report += build_detection_report(app: app_name, version: detected_version, install: "/", cpe: app_cpe);

report += '\n\n';
report += build_detection_report(app: app_name, install: "/", cpe: hw_cpe, skip_version: TRUE);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
