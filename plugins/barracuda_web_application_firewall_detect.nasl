###############################################################################
# OpenVAS Vulnerability Test
# $Id: barracuda_web_application_firewall_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Barracuda Web Application Firewall Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100419");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2010-01-04 18:09:12 +0100 (Mon, 04 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Barracuda Web Application Firewall Detection");

  script_tag(name:"summary", value:"Detection of Barracuda Web Application Firewall

The script sends a connection request to the server and attempts to detect the presence of Barracuda Web
Application Firewall and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.barracuda.com/products/webapplicationfirewall");


  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

url = "/cgi-mod/index.cgi";
buf = http_get_cache(port: port, item: url);

if (egrep(pattern: "<title>Barracuda Web Application Firewall", string: buf, icase: TRUE)) {
  version = 'unknown';

  vers = eregmatch(string: buf, pattern: "barracuda.css\?v=([0-9.]+)",icase:TRUE);
  if (!isnull(vers[1]))
    version = chomp(vers[1]);

  set_kb_item(name: "barracuda_waf/installed", value: TRUE);
  if (version != "unknown")
    set_kb_item(name: "barracuda_waf/version", value: version);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:barracuda:web_application_firewall:");
  if (!cpe)
    cpe = "cpe:/a:barracuda:web_application_firewall";

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Barracuda Web Application Firewall",
                                           version: version, install: "/", cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
