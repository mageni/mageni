###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_scrumworkspro_detect.nasl 10902 2018-08-10 14:20:55Z cfischer $
#
# Scrumworks Pro Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.107246");
  script_version("$Revision: 10902 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:20:55 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-09-25 16:22:38 +0700 (Mon, 25 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Scrumworks Pro Detection");

  script_tag(name:"summary", value:"Detection of ScrumWorks Pro.

The script sends a connection request to the server and attempts to detect Scrumworks Pro and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");

  script_require_ports("Services/www", 8080, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.collab.net/products/scrumworks");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8080);

res = http_get_cache(port: port, item: "/scrumworks/login");

if ('<title>Welcome to ScrumWorks' >< res && 'scrumworkspro' >< res)
{
    install = "/scrumworks/login";

    version = "unknown";
    ver = eregmatch( pattern: 'ScrumWorks version ([0-9.]+) [(]([0-9-]+ [0-9:]+ r[0-9]+)[)]', string: res);
    if (!isnull(ver[1]))
    {
       version = ver[1];
    }
    if (!isnull(ver[2]))
    {
       build = ver[2];
       set_kb_item(name: "scrumworkspro/build", value: build);
    }

    set_kb_item(name: "scrumworkspro/installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:collabnet:scrumworkspro:");

    if (!cpe)
    cpe = 'cpe:/a:collabnet:scrumworkspro';

    register_product(cpe: cpe, location: install, port: port);

     log_message(data: build_detection_report(app: "ScrumWorks Pro", version: version, install: install,
                                           cpe: cpe, concluded: ver[0]),
                port: port);
     exit(0);
}

exit(0);
