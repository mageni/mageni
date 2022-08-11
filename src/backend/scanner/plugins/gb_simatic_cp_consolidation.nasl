###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simatic_cp_consolidation.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Siemens SIMATIC CP Device Detection Consolidation
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
  script_oid("1.3.6.1.4.1.25623.1.0.140738");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-01 16:07:00 +0700 (Thu, 01 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens SIMATIC CP Device Detection Consolidation");

  script_tag(name:"summary", value:"Report the Siemens SIMATIC CP device model, hardware and firmware version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_simatic_cp_snmp_detect.nasl", "gb_simatic_cp_http_detect.nasl", "gb_simatic_cp_ftp_detect.nasl");
  script_mandatory_keys("simatic_cp/detected");

  script_xref(name:"URL", value:"https://www.siemens.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if( ! get_kb_item( "simatic_cp/detected" ) ) exit( 0 );

detected_version = "unknown";
detected_model   = "unknown";

# Version
foreach source (make_list("snmp", "http", "ftp")) {
  if (detected_version != "unknown")
    break;

  version_list = get_kb_list("simatic_cp/" + source + "/*/version");
  foreach version (version_list) {
    if (version && version != "unknown") {
      detected_version = version;
      set_kb_item(name: "simatic_cp/version", value: version);
    }
  }
}

# Model
foreach source (make_list("snmp", "http", "ftp")) {
  if (detected_model != "unknown")
    break;

  model_list = get_kb_list("simatic_cp/" + source + "/*/model");
  foreach model (model_list) {
    if (model && model != "unknown") {
      detected_model = model;
      set_kb_item(name: "simatic_cp/model", value: model);
    }
  }
}

# CPE
if (detected_model != "unknown") {
  app_name = "Siemens SIMATIC CP Device " + detected_model;

  cpe_model = tolower(ereg_replace(pattern: " ", string: detected_model, replace: "_"));

  app_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)",
                      base: 'cpe:/a:siemens:simatic_' + cpe_model + ':');
  if (!app_cpe)
    app_cpe = 'cpe:/a:siemens:simatic_' + cpe_model;

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)",
                     base: 'cpe:/o:siemens:simatic_' + cpe_model + '_firmware:');
  if (!os_cpe)
    os_cpe = 'cpe:/o:siemens:simatic_' + cpe_model + '_firmware';
}
else {
  app_name = "Siemens SIMATIC CP Device Unknown Model";

  if (detected_version != "unknown") {
    app_cpe = 'cpe:/a:siemens:simatic_cp:' + detected_version;
    os_cpe = 'cpe:/o:siemens:simatic_cp_firmware:' + detected_version;
  }
  else {
    app_cpe = 'cpe:/a:siemens:simatic_cp';
    os_cpe = 'cpe:/o:siemens:simatic_cp_firmware';
  }
}

# SNMP
if (snmp_ports = get_kb_list("simatic_cp/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    module = get_kb_item("simatic_cp/snmp/" + port + "/module");
    if (module)
      extra += '  Module:         ' + module + '\n';

    hw_version = get_kb_item("simatic_cp/snmp/" + port + "/hw_version");
    if (hw_version) {
      extra += '  HW Version:     ' + hw_version + '\n';
      replace_kb_item(name: "simatic_cp/hw_version", value: hw_version);
    }

    register_product(cpe: app_cpe, location: port + '/tcp', port: port, service: "snmp", proto: "udp");
    register_product(cpe: os_cpe, location: port + '/tcp', port: port, service: "snmp", proto: "udp");
  }
}

# HTTP
if (http_ports = get_kb_list("simatic_cp/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    module = get_kb_item("simatic_cp/http/" + port + "/module");
    if (module)
      extra += '  Module:         ' + module + '\n';

    hw_version = get_kb_item("simatic_cp/http/" + port + "/hw_version");
    if (hw_version) {
      extra += '  HW Version:     ' + hw_version + '\n';
      replace_kb_item(name: "simatic_cp/hw_version", value: hw_version);
    }

    concluded = get_kb_item("simatic_cp/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded URL:  ' + concluded + '\n';

    register_product(cpe: app_cpe, location: '/', port: port, service: "www");
    register_product(cpe: os_cpe, location: '/', port: port, service: "www");
  }
}

# FTP
if (ftp_ports = get_kb_list("simatic_cp/ftp/port")) {
  foreach port (ftp_ports) {
    extra += 'FTP on port ' + port + '/tcp\n';

    concluded = get_kb_item("simatic_cp/ftp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded:  ' + concluded + '\n';

    register_product(cpe: app_cpe, location: '/', port: port, service: "ftp");
    register_product(cpe: os_cpe, location: '/', port: port, service: "ftp");
  }
}

os_name = "Siemens SIMATIC S7 CP Firmware";

register_and_report_os(os: os_name, version: detected_version, cpe: os_cpe,
                       desc: "Siemens SIMATIC CP Device Detection Consolidation", runs_key: "unixoide");

report  = build_detection_report(app: app_name, version: detected_version,
                                 install: "/", cpe: app_cpe);
report += '\n\n';
report += build_detection_report(app: os_name, version: detected_version,
                                 install: "/", cpe: os_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
