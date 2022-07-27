###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simatic_hmi_consolidation.nasl 12659 2018-12-05 09:26:36Z cfischer $
#
# Siemens SIMATIC HMI Device Detection Consolidation
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141684");
  script_version("$Revision: 12659 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 10:26:36 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-11-14 15:35:48 +0700 (Wed, 14 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens SIMATIC HMI Device Detection Consolidation");

  script_tag(name:"summary", value:"Report the Siemens SIMATIC HMI device model, hardware and firmware version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_simatic_hmi_snmp_detect.nasl", "gb_simatic_hmi_http_detect.nasl");
  script_mandatory_keys("simatic_hmi/detected");

  script_xref(name:"URL", value:"https://www.siemens.com/global/en/home/products/automation/simatic-hmi.html");

  exit(0);
}

include("host_details.inc");

if (!get_kb_item("simatic_hmi/detected"))
  exit(0);

detected_fw_version = "unknown";
detected_hw_version = "unknown";
detected_model      = "unknown";

foreach source (make_list("http", "snmp")) {

  fw_version_list = get_kb_list("simatic_hmi/" + source + "/*/fw_version");
  foreach fw_version (fw_version_list) {
    if (fw_version && fw_version != "unknown") {
      detected_fw_version = fw_version;
      set_kb_item(name: "simatic_hmi/fw_version", value: fw_version);
      break;
    }
  }

  hw_version_list = get_kb_list("simatic_hmi/" + source + "/*/hw_version");
  foreach hw_version (hw_version_list) {
    if (hw_version && hw_version != "unknown") {
      detected_hw_version = hw_version;
      set_kb_item(name: "simatic_hmi/hw_version", value: hw_version);
      break;
    }
  }

  model_list = get_kb_list("simatic_hmi/" + source + "/*/model");
  foreach model (model_list) {
    if (model && model != "unknown") {
      detected_model = model;
      set_kb_item(name: "simatic_hmi/model", value: model);
      break;
    }
  }
}

# https://cache.industry.siemens.com/dl/files/300/109481300/att_871072/v5/109481300_Panel_SecurityGuidelines_en.pdf
# Page 9 "Panel operating system"
# Basic Panels
# SIMATIC HMI Basic Panels have an operating system that is configured and created by Siemens.
# Comfort Panels
# SIMATIC HMI Comfort Panels have a "WinCE Embedded" operating system specially configured for SIEMENS.
# nb: If no "Comfort" and "Basic" is included we're assuming Windows CE for now.
if ("Comfort" >< detected_model || "Basic" >!< detected_model) {
  os_name = "Windows CE";
  os_cpe  = "cpe:/o:microsoft:windows_ce";
} else {
  os_name = "Siemens SIMATIC HMI OS";
  os_cpe  = "cpe:/o:siemens:simatic_hmi_os";
}

register_and_report_os(os: os_name, cpe: os_cpe, desc: "Siemens SIMATIC HMI Device Detection Consolidation", runs_key: "windows");

app_name = "Siemens SIMATIC HMI ";
hw_name = "Siemens SIMATIC HMI ";

if (detected_model != "unknown") {
  _detected_model = str_replace(find: " ", string: detected_model, replace: "_" );
  _detected_model = tolower( _detected_model );
  app_name += detected_model + " Firmware";
  app_cpe = "cpe:/a:siemens:simatic_hmi_" + _detected_model + "_firmware";
  hw_name += detected_model;
  hw_cpe = "cpe:/h:siemens:simatic_hmi_" + _detected_model;
} else {
  app_name += " Unknown Model Firmware";
  app_cpe = "cpe:/a:siemens:simatic_hmi_unknown_model_firmware";
  hw_name += " Unknown Model";
  hw_cpe = "cpe:/h:siemens:simatic_hmi_unknown_model";
}

if (detected_fw_version != "unknown")
  app_cpe += ":" + detected_fw_version;

if (detected_hw_version != "unknown")
  hw_cpe += ":" + detected_hw_version;

if (snmp_ports = get_kb_list("simatic_hmi/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    concluded = get_kb_item('simatic_hmi/snmp/' + port + '/concluded');
    if (concluded)
      extra += 'Concluded from SNMP SysDesc: ' + concluded + '\n';

    register_product(cpe: app_cpe, location: port + '/tcp', port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: port + '/tcp', port: port, service: "snmp", proto: "udp");
  }
}

if (http_ports = get_kb_list("simatic_hmi/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    register_product(cpe: app_cpe, location: '/', port: port, service: "www");
    register_product(cpe: hw_cpe, location: '/', port: port, service: "www");
  }
}

report  = build_detection_report(app: app_name, version: detected_fw_version,
                                 install: "/", cpe: app_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, version: detected_hw_version,
                                 install: "/", cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);