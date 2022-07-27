###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nuxeo_platform_detect.nasl 10855 2018-08-09 09:11:30Z cfischer $
#
# Nuxeo Platform Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.106695");
  script_version("$Revision: 10855 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-09 11:11:30 +0200 (Thu, 09 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-03-27 14:18:27 +0700 (Mon, 27 Mar 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Nuxeo Platform Detection");

  script_tag(name:"summary", value:"Detection of Nuxeo Platform.

  The script sends a HTTP connection request to the server and attempts to detect the presence of Nuxeo Platform and
  to extract its version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.nuxeo.com/products/content-management-platform/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8080);
res = http_ka_recv_buf(port: port, url: "/nuxeo/login.jsp");

if ("nxtimezone.js" >< res && "nxstartup.faces" >< res && "Nuxeo and respective authors" >< res) {

  version = "unknown";
  install = "/nuxeo";

  vers = eregmatch(pattern: '&nbsp;.{10}([^\r\n]+)', string: res);
  if (!isnull(vers[1])) {
    version = chomp(vers[1]);
    set_kb_item(name: "nuxeo_platform/version", value: version);
  }

  set_kb_item(name: "nuxeo_platform/installed", value: TRUE);

  cpe_vers = str_replace(string: tolower(version), find: " ", replace: "-");
  cpe = build_cpe(value: cpe_vers, exp: "([0-9lts.-]+)", base: "cpe:/a:nuxeo:platform:");
  if (!cpe)
    cpe = 'cpe:/a:nuxeo:platform';

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Nuxeo Platform", version: version, install: install ,
                                           cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
