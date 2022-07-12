###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_bigfix_remote_control_detect.nasl 4700 2016-12-07 10:05:52Z ckuerste $
#
# IBM BigFix Remote Control Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106414");
  script_version("$Revision: 4700 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-07 11:05:52 +0100 (Wed, 07 Dec 2016) $");
  script_tag(name:"creation_date", value:"2016-11-28 11:22:24 +0700 (Mon, 28 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IBM BigFix Remote Control Detection");

  script_tag(name:"summary", value:"Detection of IBM BigFix Remote Control

  The script sends a connection request to the server and attempts to detect the presence of IBM BigFix Remote
Control and to extract its version");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

req = http_get(port: port, item: "/trc/");
res = http_keepalive_send_recv(port: port, data: req);

if (("<title>IBM BigFix Remote Control" >< res ||
     res =~ "<title>(IBM|Tivoli) Endpoint Manager for Remote Control") && 'action="/trc/logon.do' >< res) {
  version = "unknown";

  vers = eregmatch(pattern: 's_about_version="([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "ibm/bigfix_remote_control/version", value: version);
  }

  set_kb_item(name: "ibm/bigfix_remote_control/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:bigfix_remote_control:");
  if (!cpe)
    cpe = 'cpe:/a:ibm:bigfix_remote_control';

  register_product(cpe: cpe, location: "/trc", port: port, service: "www");

  log_message(data: build_detection_report(app: "IBM BigFix Remote Control", version: version, install: "/trc",
                                           cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
