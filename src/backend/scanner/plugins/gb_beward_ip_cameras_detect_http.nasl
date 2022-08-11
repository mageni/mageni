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
  script_oid("1.3.6.1.4.1.25623.1.0.114070");
  script_version("$Revision: 13890 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 16:36:04 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-13 14:52:10 +0100 (Wed, 13 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Beward IP Camera Detection(HTTP)");

  script_tag(name:"summary", value:"Detection of Beward IP cameras via HTTP.

  The script sends a connection request to the server and attempts to detect the web interface for the Beward IP camera.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.beward.net/category/10");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

url = "/profile";
res = http_get_cache(port: port, item: url);

#initProdNbr="N100"; BrandCopyright="Beward R&D Co., Ltd. ";
if(res =~ 'initProdNbr="([^"]+)";' && res =~ 'BrandCopyright="Beward\\s*R&D\\s*Co.,\\s*Ltd.\\s*";') {

  version = "unknown";
  model = "unknown";

  mod = eregmatch(pattern: 'initProdNbr="([^"]+)";', string: res);
  if(!isnull(mod[1])) {
    model = string(mod[1]);
    set_kb_item(name: "beward/ip_camera/http/" + port + "/concluded", value:mod[0] );
  }

  set_kb_item(name: "beward/ip_camera/detected", value: TRUE);
  set_kb_item(name: "beward/ip_camera/http/detected", value: TRUE);
  set_kb_item(name: "beward/ip_camera/http/port", value: port);
  set_kb_item(name: "beward/ip_camera/http/" + port + "/detected", value: TRUE);
  set_kb_item(name: "beward/ip_camera/http/" + port + "/model", value: model);
  set_kb_item(name: "beward/ip_camera/http/" + port + "/version", value: version);
  set_kb_item(name: "beward/ip_camera/http/" + port + "/concludedurl", value: report_vuln_url(port: port, url: url, url_only: TRUE));
}

exit(0);