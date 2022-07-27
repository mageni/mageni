###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_barracuda_spam_virus_firewall_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Barracuda Spam & Virus Firewall Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

  script_oid("1.3.6.1.4.1.25623.1.0.100846");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2010-10-06 12:55:58 +0200 (Wed, 06 Oct 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Barracuda Spam & Virus Firewall Detection");

  script_tag(name:"summary", value:"Detection of Barracuda Spam & Virus Firewall

The script sends a connection request to the server and attempts to detect the presence of Barracuda Spam &
Virus Firewall and to extract its version");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8000);
  script_mandatory_keys("BarracudaHTTP/banner");

  script_xref(name:"URL", value:"https://www.barracuda.com/products/emailsecuritygateway");


  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default: 8000);

banner = get_http_banner(port: port);
if ("Server: BarracudaHTTP" >!< banner)
  exit(0);

url = "/cgi-mod/index.cgi";
req = http_get(item: url, port: port);
buf = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

if ("<title>Barracuda Spam & Virus Firewall: Welcome" >< buf &&  "Barracuda Login Page" >< buf) {
  version = "unknown";
  vers = eregmatch(string: buf, pattern: "/barracuda.css\?v=([0-9.]+)", icase: TRUE);
  if (!isnull(vers[1]) ) {
    version = vers[1];
  }

  set_kb_item(name: "barracuda_spam_virus_fw/installed", value: TRUE);
  if (version != "unknown")
    set_kb_item(name: "barracuda_spam_virus_fw/version", value: version);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/h:barracuda_networks:barracuda_spam_firewall:");
  if (!cpe)
    cpe = "cpe:/h:barracuda_networks:barracuda_spam_firewall";

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Barracuda Spam and Virus Firewall", version: version,
                                           install: "/", cpe: cpe, concluded: vers[0]),
              port: port);

  exit(0);
}

exit(0);

