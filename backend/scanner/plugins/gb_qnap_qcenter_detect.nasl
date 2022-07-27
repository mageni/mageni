###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qnap_qcenter_detect.nasl 10896 2018-08-10 13:24:05Z cfischer $
#
# QNAP Q'center Virtual Appliance Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.141310");
  script_version("$Revision: 10896 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:24:05 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-07-17 16:08:27 +0200 (Tue, 17 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("QNAP Q'center Virtual Appliance Detection");

  script_tag(name:"summary", value:"Detection of QNAP Q'center Virtual Appliance.

The script sends a connection request to the server and attempts to detect QNAP Q'center Virtual Appliance and to
extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8081, 9443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.qnap.com/solution/qcenter/index.php");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8081);

res = http_get_cache(port: port, item: "/qcenter/qcenter/index.html");

if ("<title>Q'center</title>" >< res && 'src="settings.js' >< res) {
  version = "unknown";

  vers = eregmatch(pattern: "\.js\?_v=([0-9.]+)", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "qnap_qcenter/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:qnap:qcenter:");
  if (!cpe)
    cpe = 'cpe:/a:qnap:qcenter';

  register_product(cpe: cpe, location: "/qcenter", port: port);

  log_message(data: build_detection_report(app: "QNAP Q'center Virtual Appliance", version: version,
                                           install: "/qcenter", cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
