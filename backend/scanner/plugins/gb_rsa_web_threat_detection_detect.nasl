###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rsa_web_threat_detection_detect.nasl 10896 2018-08-10 13:24:05Z cfischer $
#
# RSA Web Threat Detection (WTD) Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.141149");
  script_version("$Revision: 10896 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:24:05 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-06-06 16:14:39 +0700 (Wed, 06 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("RSA Web Threat Detection (WTD) Detection");

  script_tag(name:"summary", value:"RSA Web Threat Detection (WTD).

The script sends a connection request to the server and attempts to detect RSA Web Threat Detection (WTD) and to
extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.rsa.com/en-us/products/fraud-prevention/account-takeover-prevention");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

url = '/js/login.js';
res = http_get_cache(port: port, item: url);

if ("RSA Web Threat Detection Administration" >< res) {
  version = "unknown";

  vers = eregmatch(pattern: 'function\\(\\)\\{return"([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = url;
  }

  set_kb_item(name: "rsa_web_threat_detection/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:emc:rsa_web_threat_detection:");
  if (!cpe)
    cpe = 'cpe:/a:emc:rsa_web_threat_detection';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "RSA Web Threat Detection", version: version, install: "/",
                                           cpe: cpe, concluded: vers[1], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
