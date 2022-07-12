###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_h2o_http_server_detect.nasl 10891 2018-08-10 12:51:28Z cfischer $
#
# H2O HTTP Server Version Detection
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806993");
  script_version("$Revision: 10891 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:51:28 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-01-25 13:12:26 +0530 (Mon, 25 Jan 2016)");
  script_name("H2O HTTP Server Version Detection");

  script_tag(name:"summary", value:"Detection of installed version
  of H2O HTTP Server.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80, 443);
  script_mandatory_keys("h2o/banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");


h2oport = get_http_port(default:443);

banner = get_http_banner(port: h2oport);
if ("Server: h2o" >!< banner)
  exit(0);

version = "unknown";

vers = eregmatch(pattern:"Server: h2o/([0-9a-zA-Z.-]+)", string:banner);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name:"h2o/installed", value:TRUE);

cpe = build_cpe(value:tolower(version), exp:"^([0-9a-zA-Z.-]+)", base:"cpe:/a:h2o_project:h2o:");
if (!cpe)
  cpe= "cpe:/a:h2o_project:h2o";

register_product(cpe:cpe, location:"/", port:h2oport);

log_message(data: build_detection_report(app: "H2O HTTP Server", version: version, install: "/", cpe: cpe,
                                         concluded: vers[0]),
            port: h2oport);
exit(0);
