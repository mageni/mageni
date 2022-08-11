# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.114099");
  script_version("2019-05-21T11:38:16+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-21 11:38:16 +0000 (Tue, 21 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-14 14:09:25 +0200 (Tue, 14 May 2019)");
  script_name("Pearl IP Cameras Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installation of
  Pearl IP Cameras.

  This script sends an HTTP GET request and tries to ensure the presence of
  a Pearl IP Camera.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

#Note: This software is nearly identical to the one used by Beward -> gb_beward_ip_cameras_detect_http.nasl
#and nearly identical to the one used by Zavio -> gb_zavio_ip_cameras_detect.nasl
#as well as TP-Link -> gb_tp_link_ip_cameras_detect.nasl

port = get_http_port(default: 80);

url = "/profile";
res = http_get_cache(port: port, item: url);

#initProdNbr="PX-3690"; initBrand="Pearl";
if(res =~ 'initProdNbr="([^"]+)";' && (res =~ 'BrandCopyright="Pearl\\s*";' || res =~ 'initBrand="Pearl\\s*";')) {
  version = "unknown";
  model = "unknown";

  mod = eregmatch(pattern: 'initProdNbr="([^"]+)";', string: res);
  if(!isnull(mod[1])) {
    model = string(mod[1]);
  }

  set_kb_item(name: "pearl/ip_camera/detected", value: TRUE);
  if(model != "unknown") {
    cpe_model = str_replace(string: tolower(model), find: " ", replace: "_");
    hw_cpe = "cpe:/h:pearl:ip_camera_" + cpe_model + ":";
    os_cpe = "cpe:/o:pearl:ip_camera_" + cpe_model + "_firmware";
    os_name = "Pearl IP Camera " + model + " Firmware";
    extra_info = "Detected model: " + model;
  } else {
    hw_cpe = "cpe:/h:pearl:ip_camera:";
    os_cpe = "cpe:/o:pearl:ip_camera_unknown_model_firmware";
  }

  register_and_report_os(os: os_name, cpe: os_cpe, desc: "Pearl IP Cameras Remote Detection", runs_key: "unixoide");

  conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "Pearl IP Camera",
                          ver: version,
                          base: hw_cpe,
                          expr: "^([0-9.]+)",
                          insloc: "/",
                          regPort: port,
                          regService: "www",
                          conclUrl: conclUrl,
                          extra: extra_info);
}

exit(0);
