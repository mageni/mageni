###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_websense_triton_detect.nasl 10702 2018-08-01 08:27:30Z cfischer $
#
# Websense Triton Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106001");
  script_version("$Revision: 10702 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-01 10:27:30 +0200 (Wed, 01 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-06-03 10:11:53 +0700 (Wed, 03 Jun 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Websense Triton Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 9443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Websense Triton.

  The script sends a connection request to the server and attempts to detect Websense Triton.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default: 9443);

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + '/triton/login/pages/loginPage.jsf';
  req = http_get(item: url, port: port);
  buf = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

  if (buf =~ "HTTP/1\.. 200" && buf =~ "TRITON Unified Security Center") {
    vers = string("unknown");
    url = dir + '/triton-help/en/first.htm';
    req = http_get(item: url, port: port);
    buf = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);
    version = eregmatch(string: buf, pattern: '<div class="wbsnversion">(v[0-9.x]+)</div>', icase: TRUE);
    if (!isnull(version[1]))
      vers = chomp(version[1]);

    set_kb_item(name: string("www/", port, "/websense_triton"), value: vers);
    set_kb_item(name: "websense_triton/installed", value: TRUE);

    cpe = build_cpe(value: vers, exp: "^(v[0-9.x]+)", base: "cpe:/a:websense:triton:");
    if (isnull(cpe))
      cpe = 'cpe:/a:websense:triton';

    register_product(cpe: cpe, location: install, port: port);

    log_message(data: build_detection_report(app:"Websense Triton", version: vers, install: install,
                                             cpe: cpe, concluded: version[0]), port: port);
  }
}

exit(0);
