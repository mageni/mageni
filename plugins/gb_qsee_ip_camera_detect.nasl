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
  script_oid("1.3.6.1.4.1.25623.1.0.114000");
  script_version("2019-07-02T11:52:11+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-07-02 11:52:11 +0000 (Tue, 02 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-05-29 13:16:48 +0200 (Wed, 29 May 2019)");
  script_name("Q-See IP Camera Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installation of
  Q-See's IP camera software.

  This script sends an HTTP GET request and tries to ensure the presence of
  the Q-See IP camera web interface.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

#Note: This software (Web3.0) is very similar to Dahua's -> gb_dahua_devices_detect.nasl
#And this one as well -> gb_amcrest_ip_camera_detect.nasl

port = get_http_port(default: 8080);

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

conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);

register_and_report_os(os: os_name, cpe: os_cpe, desc: "Q-See IP Camera Remote Detection", runs_key: "unixoide");

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