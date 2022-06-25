###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_basler_ip_camera_detect.nasl 11328 2018-09-11 12:32:47Z tpassfeld $
#
# Basler IP Camera Remote Detection
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114029");
  script_version("$Revision: 11328 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-11 14:32:47 +0200 (Tue, 11 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-10 12:17:48 +0200 (Mon, 10 Sep 2018)");
  script_name("Basler IP Camera Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  Basler IP Camera.

  This script sends HTTP GET request and try to ensure the presence of
  Basler IP Camera.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

url = "/about.html";
res = http_get_cache(port: port, item: url);

if(res =~ "(Surveillance|IP Camera) Web Client \(c\) [0-9]+ Basler AG" && res =~ "Copyright [0-9]+ by Basler AG") {

  version = "unknown";

  set_kb_item(name: "basler/ip_camera/detected", value: TRUE);

  #<td id="info-firmware">3.5.1</td>
  ver = eregmatch(pattern: '<td id="info-firmware">([0-9.a-zA-Z-]+)</td>', string: res);
  if(ver[1]) version = ver[1];

  set_kb_item(name: "basler/ip_Camera/version", value: version);

  #<td id="info-model">BIP2-1920c-dn</td>
  model = eregmatch(pattern: '<td id="info-model">([a-zA-Z0-9-]+)</td>', string: res);
  if(model[1]) set_kb_item(name: "basler/ip_camera/model", value: model[1]);

  cpe = "cpe:/a:basler:ip_camera:";

  conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "Basler IP Camera",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: "/",
                          regPort: port,
                          conclUrl: conclUrl);
}

exit(0);
