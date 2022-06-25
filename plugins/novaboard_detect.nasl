###############################################################################
# OpenVAS Vulnerability Test
# $Id: novaboard_detect.nasl 13987 2019-03-05 07:41:55Z cfischer $
#
# NovaBoard Detection
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100477");
  script_version("$Revision: 13987 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 08:41:55 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-01-29 17:41:41 +0100 (Fri, 29 Jan 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("NovaBoard Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running NovaBoard, an Open Source forum solution.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);
if (!can_host_php(port: port))
  exit(0);

foreach dir(make_list_unique("/novaboard", "/forum", "/board", cgi_dirs(port: port))) {

  install = dir;
  if (dir == "/")
    dir = "";

  buf = http_get_cache(item: dir + "/index.php", port: port );
  if (!buf)
    continue;

  if (egrep(pattern: "Powered By NovaBoard", string: buf, icase: TRUE)) {

    vers = "unknown";
    version = eregmatch(string: buf, pattern: "Powered by <a [^>]+>NovaBoard v([0-9.]+)", icase: TRUE);
    if (!isnull(version[1]) )
      vers = version[1];

    set_kb_item(name: "novaboard/detected", value: TRUE);

    cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:novaboard:novaboard:");
    if (!cpe)
      cpe = "cpe:/a:novaboard:novaboard";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "NovaBoard", version: vers, install: install, cpe: cpe,
                                             concluded: version[0]),
                port: port);
    exit(0);
  }
}

exit(0);