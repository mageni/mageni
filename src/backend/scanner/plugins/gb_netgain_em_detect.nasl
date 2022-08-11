###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgain_em_detect.nasl 10894 2018-08-10 13:09:25Z cfischer $
#
# NetGain Enterprise Manager Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.106631");
  script_version("$Revision: 10894 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:09:25 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-03-07 08:12:26 +0700 (Tue, 07 Mar 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NetGain Enterprise Manager Detection");

  script_tag(name:"summary", value:"Detection of NetGain Enterprise Manager

The script sends a HTTP connection request to the server and attempts to detect the presence of NetGain Enterprise
Manager and to extract its version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.netgain-systems.com/netgain-enterprise-manager/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/");

if (res =~ "<title>NetGain (Enterprise Manager|EM)" && res =~"NetGain Systems.*All rights reserved") {
  version = "unknown";

  vers = eregmatch(pattern: '<div class="version">v([0-9.]+)( build ([0-9]+))?', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    if (!isnull(vers[3]))
      version += "." + vers[3];
    set_kb_item(name: "netgain_em/version", value: version);
  }

  set_kb_item(name: "netgain_em/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:netgain:enterprise_manager:");
  if (!cpe)
    cpe = "cpe:/a:netgain:enterprise_manager";

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "NetGain Enterprise Manager", version: version, install: "/",
                                           cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
