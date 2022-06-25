###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asustor_adm_detect.nasl 10913 2018-08-10 15:35:20Z cfischer $
#
# ASUSTOR Data Master (ADM) Detection
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141250");
  script_version("$Revision: 10913 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:35:20 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-06-29 13:36:40 +0200 (Fri, 29 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ASUSTOR Data Master (ADM) Detection");

  script_tag(name:"summary", value:"Detection of ASUSTOR Data Master (ADM).

The script sends a connection request to the server and attempts to detect ASUSTOR Data Master (ADM) and to
extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443, 8000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.asustor.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8000);

res = http_get_cache(port: port, item: "/portal/");

if ("login-nas-model" >< res && "nasModel =" >< res && "fwType = " >< res) {
  version = "unknown";

  # nasModel ='AS3102T',
  mod = eregmatch(pattern: "nasModel ='([^']+)", string: res);
  if (!isnull(mod[1])) {
    model = mod[1];
    set_kb_item(name: "asustor_adm/model", value: model);
  }

  # var _dcTag = '3.1.2.RHG1',
  vers = eregmatch(pattern: "var _dcTag = '([^']+)", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "asustor_adm/detected", value: TRUE);

  cpe = build_cpe(value: tolower(version), exp: "^([0-9a-z.]+)", base: "cpe:/h:asustor:adm_firmware:");
  if (!cpe)
    cpe = 'cpe:/h:asustor:adm_firmware';

  register_product(cpe: cpe, location: "/portal", port: port);

  log_message(data: build_detection_report(app: "ASUSTOR Data Master " + model, version: version,
                                           install: "/portal", cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
