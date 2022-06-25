##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vtscada_detect.nasl 10905 2018-08-10 14:32:11Z cfischer $
#
# VTScada Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.106905");
  script_version("$Revision: 10905 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:32:11 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-06-23 15:38:36 +0700 (Fri, 23 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("VTScada Detection");

  script_tag(name:"summary", value:"Detection of VTScada.

The script sends a connection request to the server and attempts to detect VTScada and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.trihedral.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/");

if ("Server: VTScada" >!< res && res !~ "Location: /scada/*./anywhere/Page")
  exit(0);

url = eregmatch(pattern: "Location: ((.*)/anywhere/Page)", string: res);
if (isnull(url[1]))
  exit(0);

location = url[2];
url = url[1];

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if ("<title>VTScada Anywhere login</title>" >< res) {
  version = "unknown";

  vers = eregmatch(pattern: "anywhereClientServerVersion='([0-9.]+)", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "vtscada/version", value: version);
  }

  set_kb_item(name: "vtscada/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:trihedral:vtscada:");
  if (!cpe)
    cpe = 'cpe:/a:trihedral:vtscada';

  register_product(cpe: cpe, location: location, port: port);

  log_message(data: build_detection_report(app: "VTScada", version: version, install: location, cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
