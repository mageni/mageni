###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_endpoint_manager_for_remote_control_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# IBM Endpoint Manager for Remote Control Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813320");
  script_version("$Revision: 11885 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-05-02 16:58:59 +0530 (Wed, 02 May 2018)");
  script_name("IBM Endpoint Manager for Remote Control Detection");
  script_tag(name:"summary", value:"Detects the installed version of
 IBM Endpoint Manager for Remote Control.

 This script sends HTTP GET request and try to detect the presence of
 IBM Endpoint Manager for Remote Control from the response.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

trcport = get_http_port(default:80);

rcvRes = http_get_cache(item:"/trc/", port:trcport);

if(rcvRes =~ "<title>Tivoli Endpoint Manager for Remote Control.*</title>"&&
   '>User ID:' >< rcvRes && '>Password:' >< rcvRes)
{

  version = 'unknown';
  set_kb_item( name:"ibm_endpoint_manager_for_remote_control/installed",value:TRUE );

  vers = eregmatch(pattern:'<title>Tivoli Endpoint Manager for Remote Control ([0-9.]+)', string:rcvRes);

  if(!vers[1]){
    vers = eregmatch(pattern:'js_about_version="([0-9.]+)"', string:rcvRes);
  }

  if(vers[1]){
    version = vers[1];
    set_kb_item(name: "ibm_endpoint_manager_for_remote_control/version", value: version);
  }

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:ibm:endpoint_manager_for_remote_control:");
  if(isnull(cpe))
    cpe = "cpe:/a:ibm:endpoint_manager_for_remote_control";

  register_product(cpe:cpe, location:'/', port:trcport);

  log_message(data: build_detection_report(app:"IBM Endpoint Manager for Remote Control",
                                           version:version,
                                           install:'/',
                                           cpe:cpe,
                                           concluded: version),
                                           port:trcport);

  exit(0);
}
exit(0);
