###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netscape_enterprise_server_detect.nasl 11408 2018-09-15 11:35:21Z cfischer $
#
# Netscape Enterprise Server Version Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811543");
  script_version("$Revision: 11408 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:35:21 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-07-28 13:24:46 +0530 (Fri, 28 Jul 2017)");
  script_name("Netscape Enterprise Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed version
  of Netscape Enterprise Server.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

netport = get_http_port(default:80);

banner = get_http_banner(port:netport);

if(banner && "Server: Netscape-Enterprise" >< banner)
{
  netver = "Unknown";

  set_kb_item(name:"Netscape/Enterprise/Server/Installed", value:TRUE);

  netver = eregmatch( pattern:'Netscape-Enterprise/([0-9A-Z. ]+)', string:banner);
  if(netver[1])
  {
    netver = ereg_replace(pattern:" ", replace:".", string:netver[1]);
    set_kb_item(name:"Netscape/Enterprise/Server/version", value:netver);
  }

  cpe = build_cpe(value: netver, exp:"^([0-9A-Z.]+)", base:"cpe:/a:netscape:enterprise_server:");
  if(!cpe)
    cpe = "cpe:/a:netscape:enterprise_server";

  register_product(cpe:cpe, location:"/", port:netport);

  log_message(data: build_detection_report(app: "Netscape Enterprise Server",
                                           version: netver,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: netver),
                                           port: netport);
  exit(0);
}
