###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_arkeia_virtual_appliance_detect.nasl 10896 2018-08-10 13:24:05Z cfischer $
#
# Arkeia Appliance Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803759");
  script_version("$Revision: 10896 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:24:05 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2013-09-18 13:34:54 +0530 (Wed, 18 Sep 2013)");
  script_name("Arkeia Appliance Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the Arkeia Appliance and attempts
  to extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

buf = http_get_cache(item:"/", port:http_port);
if("Arkeia Appliance<" >!< buf && ">Arkeia Software<" >!< buf){
  exit(0);
}

version = eregmatch(string:buf, pattern:"v([0-9.]+)<");
if(version[1]) {
  set_kb_item(name: string("www/", http_port, "/ArkeiaAppliance"), value: version[1]);
}

set_kb_item(name:"ArkeiaAppliance/installed",value:TRUE);

cpe = build_cpe(value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:knox_software:arkeia_appliance:");
if(isnull(cpe))
  cpe = 'cpe:/a:knox_software:arkeia_appliance';

register_product(cpe:cpe, location:'/', port:http_port, service: "www");

log_message(data: build_detection_report(app:"Arkeia Appliance",
                                         version:version[1],
                                         install:'/',
                                         cpe:cpe,
                                         concluded: version[1]),
                                         port:http_port);
exit(0);
