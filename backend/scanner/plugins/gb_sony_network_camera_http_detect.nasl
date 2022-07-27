# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.114022");
  script_version("2022-03-14T12:10:10+0000");
  script_tag(name:"last_modification", value:"2022-03-15 11:02:07 +0000 (Tue, 15 Mar 2022)");
  script_tag(name:"creation_date", value:"2018-08-21 15:13:40 +0200 (Tue, 21 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sony Network Camera (SNC) Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Sony Network Camera (SNC) devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://pro.sony/en_EE/products/ip-cameras");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("os_func.inc");

port = http_get_port(default: 80);

# The response has something like e.g. the following:
#
# var ModelName="SNC-RZ25N"
# var SoftVersion="1.40"
# var TitleBar="Sony Network Camera SNC-RZ25"
#
# or:
#
# var ModelName="SNC-DF40N"
# var SoftVersion="1.18"
# var TitleBar="Sony  SNC-DF40 (Shop)"
#
# or:
#
# var ModelName="SNC-P5"
# var SoftVersion="1.11"
# var TitleBar="Sony Network Camera SNC-P5"
#
url = "/command/inquiry.cgi?inqjs=sysinfo";
res = http_get_cache(port: port, item: url);
if(!res)
  exit(0);

if((res =~ "^HTTP/1\.[01] 200" && ('var ModelName="' >< res || 'var SoftVersion="' >< res || 'var TitleBar="' >< res)) ||
   (res =~ "^HTTP/1\.[01] 401" && 'Basic realm="Sony Network Camera SNC' >< res)
  ) {

  version = "unknown";
  model = "unknown";
  install = "/";
  hw_name = "Sony Network Camera (SNC)";
  hw_cpe = "cpe:/h:sony:network_camera";
  os_name = hw_name + " Firmware";
  os_cpe = "cpe:/o:sony:network_camera_firmware";

  # var SoftVersion="1.30"
  vers = eregmatch(pattern: 'var [Ss]oft[Vv]ersion="([0-9.]+)', string: res);
  if(vers[1]) {
    version = vers[1];
    concluded = "  " + vers[0];
    os_cpe += ":" + version;
  }

  # var ModelName="SNC-RZ25N"
  mod = eregmatch(pattern: 'var ([Mm]odel[Nn]ame="SNC-([0-9a-zA-Z]+))|Basic realm="Sony Network Camera SNC-([0-9a-zA-z]+)"', string: res);
  if(mod[2])
    model = mod[2];
  else if(mod[3])
    model = mod[3];

  if(mod) {
    if(concluded)
      concluded += '\n';
    concluded += "  " + mod[0];
    hw_name += " " + model;
    hw_cpe += "_" + tolower(model);
  } else {
    hw_name += " Unknown Model";
    hw_cpe += "_unknown_model";
  }

  os_register_and_report(os: os_name, cpe: os_cpe, runs_key: "unixoide",
                         desc: "Sony Network Camera (SNC) Detection (HTTP)");

  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "sony/network_camera/detected", value: TRUE);
  set_kb_item(name: "sony/network_camera/" + port + "/detected", value: TRUE);
  set_kb_item(name: "sony/network_camera/http/detected", value: TRUE);
  set_kb_item(name: "sony/network_camera/http/" + port + "/detected", value: TRUE);

  report  = build_detection_report(app: os_name, version: version, install: install, cpe: os_cpe);
  report += '\n\n';
  report += build_detection_report(app: hw_name, install: install, cpe: hw_cpe, skip_version: TRUE);

  if (concluded)
    report += '\n\nConcluded from version/product identification result:\n' + concluded;

  report += '\n\nConcluded from version/product identification location:\n  ' + conclUrl;

  log_message(port: port, data: chomp(report));
}

exit(0);
