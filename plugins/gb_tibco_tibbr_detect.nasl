###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tibco_tibbr_detect.nasl 10890 2018-08-10 12:30:06Z cfischer $
#
# TIBCO tibbr Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140604");
  script_version("$Revision: 10890 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:30:06 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-12-14 13:28:21 +0700 (Thu, 14 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("TIBCO tibbr Detection");

  script_tag(name:"summary", value:"Detection of TIBCO tibbr.

The script sends a connection request to the server and attempts to detect TIBCO tibbr and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.tibbr.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

res = http_get_cache(port: port, item: "/tibbr/web/login");

if ("h2>Welcome to tibbr</h2>" >< res && '"company_name":"TIBCO Software Inc."' >< res) {
  version = "unknown";

  # "version":"6.0.1 HF7"
  # currently don't see a possibility to distinguish between 'community' and 'enterprise'
  vers = eregmatch(pattern: '"version":"([^"]+)"', string: res);
  if (!isnull(vers[1])) {
    tmp_vers = split(vers[1], sep: ' ', keep: FALSE);
    version = tmp_vers[0];
    if (!isnull(tmp_vers[1])) {
      hotfix = tmp_vers[1];
      set_kb_item(name: "tibbr/hotfix", value: hotfix);
      extra = "Hotfix: " + hotfix;
    }
  }

  set_kb_item(name: "tibbr/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:tibco:tibbr:");
  if (!cpe)
    cpe = 'cpe:/a:tibco:tibbr';

  register_product(cpe: cpe, location: "/tibbr", port: port);

  log_message(data: build_detection_report(app: "TIBCO tibbr", version: version, install: "/tibbr", cpe: cpe,
                                           concluded: vers[0], extra: extra),
              port: port);
  exit(0);
}

exit(0);
