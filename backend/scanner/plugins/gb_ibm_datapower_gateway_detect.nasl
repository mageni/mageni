###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_datapower_gateway_detect.nasl 11668 2018-09-28 08:33:11Z ckuersteiner $
#
# IBM DataPower Gateway Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.141536");
  script_version("$Revision: 11668 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 10:33:11 +0200 (Fri, 28 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-28 14:16:14 +0700 (Fri, 28 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IBM DataPower Gateway Detection");

  script_tag(name:"summary", value:"Detection of IBM DataPower Gateway.

The script sends a connection request to the server and attempts to detect IBM DataPower Gateway and to extract
its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.ibm.com/products/datapower-gateway");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

res = http_get_cache(port: port, item: "/dp/login.xml");

if ("login.startup(domainList" >< res && 'class="oneui"' >< res) {
  version = "unknown";

  # login.startup(domainList,"IDG",
  prefix = eregmatch(pattern: 'login.startup\\(domainList,"([^"]+)"', string: res);
  if (!isnull(prefix[1])) {
    # "IDG.7.7.1.3");
    vers = eregmatch(pattern: prefix[1] + "\.([0-9.]+)", string: res);
    if (!isnull(vers[1]))
      version = vers[1];
  }

  set_kb_item(name: "ibm_datapower_gateway/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:datapower_gateway:");
  if (!cpe)
    cpe = 'cpe:/a:ibm:datapower_gateway';

  register_product(cpe: cpe, location: "/dp", port: port);

  log_message(data: build_detection_report(app: "IBM DataPower Gateway", version: version, install: "/dp",
                                           cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
