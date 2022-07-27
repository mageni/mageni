###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rancher_detect.nasl 10908 2018-08-10 15:00:08Z cfischer $
#
# Rancher Server Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.107247");
  script_version("$Revision: 10908 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:00:08 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-10-16 16:22:38 +0200 (Mon, 16 Oct 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Rancher Detection");

  script_tag(name:"summary", value:"Detection of Rancher Server.

The script sends a connection request to the server and attempts to detect Rancher and to
extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");

  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://rancher.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8080);

url = "/login/";

res = http_get_cache(port: port, item: url);

if (res =~ "HTTP/1.. 200 OK" && "PL=rancher" >< res && "X-Rancher-Version" >< res)
{

    version = "unknown";
    ver = eregmatch( pattern: 'X-Rancher-Version: v([0-9.]+)', string: res);

    if (!isnull(ver[1]))
    {
        version = ver[1];
        set_kb_item(name: "rancher/version", value: version);
    }

    set_kb_item(name: "rancher/installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:rancher:rancher:");

    if (!cpe)
        cpe = 'cpe:/a:rancher:rancher';

    register_product(cpe: cpe, location: "/", port: port, service: "www");

    log_message(data: build_detection_report(app: "Rancher", version: version, install: "/",
                cpe: cpe, concluded: ver[0]),
                port: port);
    exit(0);
}

exit(0);

