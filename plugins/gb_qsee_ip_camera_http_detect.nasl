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
  script_oid("1.3.6.1.4.1.25623.1.0.114000");
  script_version("2021-11-23T14:13:02+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2019-05-29 13:16:48 +0200 (Wed, 29 May 2019)");
  script_name("Q-See IP Camera Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Q-See's IP camera software / web
  interface.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

#Note: This software (Web3.0) is very similar to Dahua's -> gb_dahua_devices_http_detect.nasl
#And this one as well -> gb_amcrest_ip_camera_http_detect.nasl

port = http_get_port(default: 8080);

url = "/web_caps/webCapsConfig";

res = http_get_cache(port: port, item: url);
if(!res)
  exit(0);

match = eregmatch(string: res, pattern: '"vendor"\\s*:\\s*"QSee"', icase: TRUE);
if(!match)
  exit(0);

concl = match[0];

#Version detection requires login.
version = "unknown";
model = "unknown";

set_kb_item(name: "qsee/ip_camera/detected", value: TRUE);
set_kb_item(name: "qsee/ip_camera/http/detected", value: TRUE);

ver = eregmatch(pattern: '"WebVersion"\\s*:\\s*"([^"]+)"', string: res);
if(!isnull(ver[1])) {
  version = string(ver[1]);
  concl += '\n' + ver[0];
}

mod = eregmatch(pattern: '"deviceType"\\s*:\\s*"([^"]+)"', string: res);
if(!isnull(mod[1])) {
  model = string(mod[1]);
  concl += '\n' + mod[0];
}

if(model != "unknown") {
  cpe_model = str_replace(string: tolower(model), find: " ", replace: "_");
  hw_cpe = "cpe:/h:qsee:ip_camera_" + cpe_model + ":";
  os_cpe = "cpe:/o:qsee:ip_camera_" + cpe_model + "_firmware";
  os_name = "Q-See IP Camera " + model + " Firmware";
  extra_info = "Detected model: " + model;
} else {
  hw_cpe = "cpe:/h:qsee:ip_camera_unknown_model:";
  os_cpe = "cpe:/o:qsee:ip_camera_unknown_model_firmware";
  os_name = "Q-See IP Camera Unknown Model Firmware";
}

conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

os_register_and_report(os: os_name, cpe: os_cpe, desc: "Q-See IP Camera Detection (HTTP)", runs_key: "unixoide");

register_and_report_cpe(app: "Q-See IP Camera",
                        ver: version,
                        concluded: concl,
                        base: hw_cpe,
                        expr: "^([0-9.]+)",
                        insloc: "/",
                        regPort: port,
                        regService: "www",
                        conclUrl: conclUrl,
                        extra: extra_info);

exit(0);