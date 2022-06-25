# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114075");
  script_version("2021-02-25T16:05:56+0000");
  script_tag(name:"last_modification", value:"2021-02-26 11:25:03 +0000 (Fri, 26 Feb 2021)");
  script_tag(name:"creation_date", value:"2019-02-20 14:23:38 +0100 (Wed, 20 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Beward IP Camera Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Beward IP camera detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_beward_ip_camera_http_detect.nasl", "gb_beward_ip_camera_upnp_detect.nasl");
  script_mandatory_keys("beward/ip_camera/detected");

  script_xref(name:"URL", value:"https://www.beward.net/category/10");

  exit(0);
}

include("host_details.inc");

if(!get_kb_item("beward/ip_camera/detected"))
  exit(0);

detected_model   = "unknown";
detected_version = "unknown";

foreach source(make_list("upnp", "http")) {

  model_list = get_kb_list("beward/ip_camera/" + source + "/*/model");
  foreach model(model_list) {
    if(model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "beward/ip_camera/model", value: model);
    }
  }

  version_list = get_kb_list("beward/ip_camera/" + source + "/*/version");
  foreach version(version_list) {
    if(version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      set_kb_item(name: "beward/ip_camera/version", value: version);
    }
  }
}

if(detected_model != "unknown") {
  cpe_model = str_replace(string: tolower(detected_model), find: " ", replace: "_");
  hw_name = "Beward " + detected_model + " IP Camera";
  hw_cpe = "cpe:/h:beward:" + cpe_model;
  os_name = "Beward " + detected_model + " IP Camera Firmware";
  os_cpe = "cpe:/o:beward:" + cpe_model + "_firmware";
} else {
  hw_name = "Beward Unknown Model IP Camera";
  hw_cpe = "cpe:/h:beward:unknown_model";
  os_name = "Beward Unknown Model IP Camera Firmware";
  os_cpe = "cpe:/o:beward:unknown_model_firmware";
}

if(detected_version != "unknown")
  os_cpe += ":" + tolower(detected_version);

register_and_report_os(os: os_name, cpe: os_cpe, desc: "Beward IP Camera Detection Consolidation", runs_key: "unixoide");

location = "/";

if(http_port = get_kb_list("beward/ip_camera/http/port")) {
  foreach port(http_port) {
    extra += '\n\nHTTP(s) on port ' + port + '/tcp';
    concluded = get_kb_item("beward/ip_camera/http/" + port + "/concluded");
    concludedurl = get_kb_item("beward/ip_camera/http/" + port + "/concludedurl");
    if(concluded)
      extra += '\nBanner: ' + concluded;
    if(concludedurl)
      extra += '\nURL: ' + concludedurl;
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
    register_product(cpe: os_cpe, location: location, port: port, service: "www");
  }
}

if(upnp_port = get_kb_list("beward/ip_camera/upnp/port")) {
  foreach port(upnp_port) {
    extra += '\n\nUPnP on port ' + port + '/udp';
    concluded = get_kb_item("beward/ip_camera/upnp/" + port + "/concluded");
    if(concluded)
      extra += '\nBanner: ' + concluded;

    register_product(cpe: hw_cpe, location: location, port: port, service: "upnp", proto: "udp");
    register_product(cpe: os_cpe, location: location, port: port, service: "upnp", proto: "udp");
  }
}

report += build_detection_report(app: hw_name,
                                 install: location,
                                 skip_version: TRUE,
                                 cpe: hw_cpe);

report += '\n\n';
report += build_detection_report(app: os_name,
                                 install: location,
                                 version: detected_version,
                                 cpe: os_cpe);

if(extra)
  report += '\n\nConcluded from exposed services:' + extra;

log_message(port: 0, data: report);

exit(0);