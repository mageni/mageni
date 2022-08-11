###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moxa_edr_g903_remote_detect.nasl 10890 2018-08-10 12:30:06Z cfischer $
#
# Moxa EDR G903 Router Remote Version Detection
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808219");
  script_version("$Revision: 10890 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:30:06 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-06-09 13:45:38 +0530 (Thu, 09 Jun 2016)");
  script_name("Moxa EDR G903 Router Remote Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Moxa EDR G903 Router.

  This script sends HTTP GET request and check for the presence of Moxa EDR G903
  Router from the response and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

edrPort = get_http_port( default:80 );
if( ! can_host_asp( port:edrPort ) ) exit( 0 );

url = "/Login.asp";

rcvRes = http_get_cache(item:url, port:edrPort);

#Project model is different for different edr series
if("<TITLE>Moxa EDR</TITLE>" >< rcvRes && "Moxa EtherDevice Secure Router" >< rcvRes &&
   "Username :" >< rcvRes && "Password :" >< rcvRes &&
   ("ProjectModel = 1" >< rcvRes || ">EDR-G903<" >< rcvRes))
{
  edrVer = "Unknown";

  set_kb_item(name:"Moxa/EDR/G903/Installed", value:TRUE);

  cpe = "cpe:/h:moxa:edr-g903";

  register_product(cpe:cpe, location:"/", port:edrPort);

  log_message(data: build_detection_report(app: "Moxa EDR G903 Router",
                                           version: edrVer,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: edrVer),
                                           port: edrPort);
}
