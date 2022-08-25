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
  script_oid("1.3.6.1.4.1.25623.1.0.114037");
  script_version("2022-08-25T06:23:20+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-08-25 06:23:20 +0000 (Thu, 25 Aug 2022)");
  script_tag(name:"creation_date", value:"2018-10-05 14:33:50 +0200 (Fri, 05 Oct 2018)");
  script_name("Hikvision IP Camera Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8081);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Hikvision IP camera devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("os_func.inc");

port = http_get_port(default: 8081);

url = "/doc/script/config/system/channelDigital.js";
res = http_get_cache(port: port, item: url);

if(!res || res !~ "^HTTP/1\.[01] 200") {
  url = "/doc/script/inc.js";
  res = http_get_cache(port: port, item: url);
}

if(!res || res !~ "^HTTP/1\.[01] 200")
  exit(0);

# nb: channelDigital.js has a huge single line (inc.js is smaller) so no egrep() here...
if(concl = eregmatch(string: res, pattern: '("/hikvision://"|\\{case"HIKVISION")', icase: FALSE)) {

  concluded = concl[0];
  version = "unknown";
  install = "/";
  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  url = "/doc/script/global_config.js";
  res = http_get_cache(port: port, item: url);
  if(!res || res !~ "^HTTP/1\.[01] 200") {
    url = "/doc/script/lib/seajs/config/sea-config.js";
    res = http_get_cache(port: port, item: url);
  }

  if(res && res =~ "^HTTP/1\.[01] 200") {

    #seajs.web_version="V4.0.1build171121" #web_version:"3.1.3.131126" #web_version: "3.0.51.170214"
    vers = eregmatch(pattern: 'seajs\\.web_version\\s*=\\s*"V([0-9.]+)[a-zA-Z]+([0-9]+)"|web_version\\s*:\\s*"([0-9.]+)"', string: res);
    if(!isnull(vers[1]) && !isnull(vers[2])) {
      version = vers[1] + "." + vers[2]; #Unifying the extracted versions for later use
      conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      concluded += '\n' + vers[0];
    } else if(!isnull(vers[3])) {
      version = vers[3];
      conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      concluded += '\n' + vers[0];
    }
  }

  set_kb_item(name: "hikvision/ip_camera/detected", value: TRUE);
  set_kb_item(name: "hikvision/ip_camera/http/detected", value: TRUE);

  hw_cpe = "cpe:/h:hikvision:ip_camera";
  hw_name = "Hikvision IP Camera";
  os_name = hw_name + " Firmware";

  os_cpe = build_cpe(value: version, exp: "^([0-9.a-z]+)", base: "cpe:/o:hikvision:ip_camera_firmware:");
  if(!os_cpe)
    os_cpe = "cpe:/o:hikvision:ip_camera_firmware";

  os_register_and_report(os: os_name, version: version, cpe: os_cpe, desc: "Hikvision IP Camera Detection (HTTP)", runs_key: "unixoide", full_cpe: TRUE);

  register_product(cpe: os_cpe, location: install, port: port, service: "www");
  register_product(cpe: hw_cpe, location: install, port: port, service: "www");

  report  = build_detection_report(app: os_name, version: version, install: install, cpe: os_cpe, concluded: concluded, concludedUrl: conclUrl);
  report += '\n\n';
  report += build_detection_report(app: hw_name, skip_version:TRUE, install: install, cpe: hw_cpe);

  log_message(port: port, data: report);
}

exit(0);
