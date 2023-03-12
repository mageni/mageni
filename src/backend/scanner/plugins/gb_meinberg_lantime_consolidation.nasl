# Copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104585");
  script_version("2023-03-10T10:09:33+0000");
  script_tag(name:"last_modification", value:"2023-03-10 10:09:33 +0000 (Fri, 10 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-02-28 15:10:50 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Meinberg LANTIME Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Meinberg LANTIME NTP Timeserver device
  detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_meinberg_lantime_snmp_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_meinberg_lantime_http_detect.nasl",
                        "gsf/gb_meinberg_lantime_mdns_detect.nasl",
                        "gsf/gb_meinberg_lantime_ssh_login_detect.nasl",
                        "gsf/gb_meinberg_lantime_ntp_detect.nasl");
  script_mandatory_keys("meinberg/lantime/detected");

  script_xref(name:"URL", value:"https://www.meinbergglobal.com/english/products/ntp-time-server.htm");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

if (!get_kb_item("meinberg/lantime/detected"))
  exit(0);

detected_model = "unknown";
detected_fw    = "unknown";

foreach source (make_list("ssh-login", "snmp", "mdns", "ntp")) {
  model_list = get_kb_list("meinberg/lantime/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "meinberg/lantime/model", value: detected_model);
      break;
    }
  }

  fw_list = get_kb_list("meinberg/lantime/" + source + "/*/fw_version");
  foreach fw (fw_list) {
    if (fw != "unknown" && detected_fw == "unknown") {
      detected_fw = fw;
      set_kb_item(name: "meinberg/lantime/firmware_version", value: detected_fw);
      break;
    }
  }
}

cpe_model = "unknown_model";
os_name = "Meinberg LANTIME Firmware";
hw_name = "Meinberg LANTIME Unknown Model";

# nb: NVD is currently using different ones (see 2016 and 2017 CVEs). The "1" are the newer ones.
hw_cpe1 = "cpe:/h:meinbergglobal:lantime_";
base_os_cpe1 = "cpe:/o:meinbergglobal:lantime_firmware";

hw_cpe2 = "cpe:/h:meinberg:lantime_";
base_os_cpe2 = "cpe:/o:meinberg:ntp_server_firmware";

if (detected_model != "unknown") {

  hw_name = "Meinberg LANTIME " + detected_model;

  # nb:
  # - This is done because the model might include /PZF but we don't want to include this in the CPE
  # - At least one unknown M3x model has been seen and we want to include the "x" here
  cpe_mod = eregmatch(pattern: "([A-Z0-9x]+)", string: detected_model, icase: FALSE);
  if (cpe_mod[1])
    cpe_model = tolower(cpe_mod[1]);
}

hw_cpe1 += cpe_model;
hw_cpe2 += cpe_model;

# nb:
# - The "nc" in V5.35nc is currently not included here because it's not clear if that is part of the
#   version
# - On older 5.x we have also seen V5.34p6 which seems to be "ok" to add it
os_cpe1 = build_cpe(value: detected_fw, exp: "^([0-9p.]+)", base: base_os_cpe1 + ":");
os_cpe2 = build_cpe(value: detected_fw, exp: "^([0-9p.]+)", base: base_os_cpe2 + ":");
if (!os_cpe1) {
  os_cpe1 = base_os_cpe1;
  os_cpe2 = base_os_cpe2;
}

# nb:
# - We're only registering a single OS CPE here on purpose, the other CPE is covered in the
#   register_product call below...
# - From https://www.meinbergglobal.com/english/products/ntp-time-server.htm#prgchar:
#   > Operating System of the SBC: Linux with nano kernel (incl. PPSkit)
os_register_and_report(os: os_name, cpe: os_cpe1, version: detected_fw, full_cpe: TRUE, port: 0,
                       desc: "Meinberg LANTIME Detection Consolidation", runs_key: "unixoide");

install = "/";

if (http_ports = get_kb_list("meinberg/lantime/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item("meinberg/lantime/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:' + concluded + '\n';

    concUrl = get_kb_item("meinberg/lantime/http/" + port + "/concludedUrl");
    if (concUrl)
      extra += '  Concluded from version/product identification location:\n' + concUrl + '\n';

    register_product(cpe: os_cpe1, location: install, port: port, service: "www");
    register_product(cpe: os_cpe2, location: install, port: port, service: "www");
    register_product(cpe: hw_cpe1, location: install, port: port, service: "www");
    register_product(cpe: hw_cpe2, location: install, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("meinberg/lantime/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';
    concluded = get_kb_item("meinberg/lantime/snmp/" + port + "/concluded");
    if (concluded)
      extra += '  SNMP sysDescr OID: ' + concluded + '\n';

    register_product(cpe: os_cpe1, location: install, port: port, proto: "udp", service: "snmp");
    register_product(cpe: os_cpe2, location: install, port: port, proto: "udp", service: "snmp");
    register_product(cpe: hw_cpe1, location: install, port: port, proto: "udp", service: "snmp");
    register_product(cpe: hw_cpe2, location: install, port: port, proto: "udp", service: "snmp");
  }
}

if (mdns_ports_and_protos = get_kb_list("meinberg/lantime/mdns/port_and_proto")) {
  foreach mdns_port_and_proto (mdns_ports_and_protos) {
    concluded = get_kb_item("meinberg/lantime/mdns/" + mdns_port_and_proto + "/concluded");
    if (concluded)
      extra += concluded + '\n';
    else
      extra += 'mDNS on port ' + mdns_port_and_proto + '\n';

    if (!exposed_port = get_kb_item("meinberg/lantime/mdns/" + mdns_port_and_proto + "/exposed_port"))
      exposed_port = 0;

    # nb:
    # - Although the service was discovered via mDNS, it actually resides on the TCP port exposed by mDNS
    # - Only seen "Remote Display Port" for the TCP port so this is used here
    register_product(cpe: os_cpe1, location: install, port: port, service: "remote_display_port");
    register_product(cpe: os_cpe2, location: install, port: port, service: "remote_display_port");
    register_product(cpe: hw_cpe1, location: install, port: port, service: "remote_display_port");
    register_product(cpe: hw_cpe2, location: install, port: port, service: "remote_display_port");
  }
}

if (ntp_ports = get_kb_list("meinberg/lantime/ntp/port")) {
  foreach port (ntp_ports) {
    extra += 'NTP on port ' + port + '/udp\n';
    concluded = get_kb_item("meinberg/lantime/ntp/" + port + "/concluded");
    if (concluded)
      extra += '  NTP banner: ' + concluded + '\n';

    register_product(cpe: os_cpe1, location: install, port: port, proto: "udp", service: "ntp");
    register_product(cpe: os_cpe2, location: install, port: port, proto: "udp", service: "ntp");
    register_product(cpe: hw_cpe1, location: install, port: port, proto: "udp", service: "ntp");
    register_product(cpe: hw_cpe2, location: install, port: port, proto: "udp", service: "ntp");
  }
}

if (ssh_login_ports = get_kb_list("meinberg/lantime/ssh-login/port")) {
  foreach port (ssh_login_ports) {
    extra += 'SSH login via port ' + port + '/tcp\n';

    concluded = get_kb_item("meinberg/lantime/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    register_product(cpe: os_cpe1, location: install, port: port, service: "ssh-login");
    register_product(cpe: os_cpe2, location: install, port: port, service: "ssh-login");
    register_product(cpe: hw_cpe1, location: install, port: port, service: "ssh-login");
    register_product(cpe: hw_cpe2, location: install, port: port, service: "ssh-login");
  }
}

report  = build_detection_report(app: os_name, version: detected_fw, install: install, cpe: os_cpe1);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: install, cpe: hw_cpe1);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
