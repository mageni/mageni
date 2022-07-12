###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_epolicy_orchestrator_detect.nasl 11407 2018-09-15 11:02:05Z cfischer $
#
# McAfee ePolicy Orchestrator (ePO) Detection
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803862");
  script_version("$Revision: 11407 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:02:05 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-08-08 18:54:25 +0530 (Thu, 08 Aug 2013)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("McAfee ePolicy Orchestrator (ePO) Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  McAfee ePolicy Orchestrator.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:8443 );

req = http_get(item:"/core/orionSplashScreen.do", port:port);
resp = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("ePolicy Orchestrator" >< resp && "McAfee" >< resp)
{
  version = "unknown";
  build = "unknown";

  vers = eregmatch(string: resp, pattern: "ePolicy Orchestrator ([0-9.]+)( \(Build: ([0-9]+)\))?");
  if (!isnull(vers[1])) {
    version =  vers[1];
    set_kb_item(name: "mcafee_ePO/version", value: version);
  }

  if (!isnull(vers[3])) {
    build = vers[3];
    set_kb_item(name: "mcafee_ePO/build", value: build);
  }

  set_kb_item(name:"mcafee_ePO/installed",value:TRUE);

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:mcafee:epolicy_orchestrator:");
  if(isnull(cpe))
    cpe = 'cpe:/a:mcafee:epolicy_orchestrator';

  register_product(cpe:cpe, location: "/", port:port);

  log_message(data: build_detection_report(app: "McAfee ePolicy Orchestrator", version: version, install: "/",
                                           cpe:cpe, concluded: vers[0], extra: "Build: " + build),
              port:port);
  exit(0);
}

exit(0);
