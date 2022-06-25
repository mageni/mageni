##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_diagnostics_server_detect.nasl 10915 2018-08-10 15:50:57Z cfischer $
#
# HP Diagnostics Server Version Detection
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802389");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10915 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:50:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-02-02 10:43:19 +0530 (Thu, 02 Feb 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("HP Diagnostics Server Version Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports(2006);

  script_tag(name:"summary", value:"Detection of HP Diagnostics Server

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## HP Diagnostics Server port
hpdsPort = 2006;
if(!get_port_state(hpdsPort)){
  exit(0);
}

rcvRes = http_get_cache(item: "/", port:hpdsPort);

if ((">HP Diagnostics" >< rcvRes && "Hewlett-Packard Development" >< rcvRes) ||
    (">HPE Diagnostics" >< rcvRes && 'diagName">Diagnostics Server' >< rcvRes))
{
  hpdiagVer = eregmatch(pattern:">Server ([0-9.]+)", string:rcvRes);
  if(!hpdiagVer){
    hpdiagVer = eregmatch(pattern:'version">Version ([0-9.]+)', string:rcvRes);
  }

  if(hpdiagVer[1])
  {
    hpdiagVer = hpdiagVer[1];
    set_kb_item(name:"www/"+ hpdsPort + "/HP/Diagnostics_Server/Ver", value:hpdiagVer);
  }

  else{
   hpdiagVer = "unknown";
  }

  set_kb_item(name:"hpdiagnosticsserver/installed",value:TRUE);

  cpe = build_cpe(value:hpdiagVer, exp:"^([0-9.]+)", base:"cpe:/a:hp:diagnostics_server:");
  if(isnull(cpe))
    cpe = 'cpe:/a:hp:diagnostics_server';

  register_product(cpe:cpe, location:"/", port:hpdsPort);

  log_message(data: build_detection_report(app: "HP Diagnostics Server", version: hpdiagVer, install: "/",
                                           cpe: cpe, concluded: 'HP Diagnostics Server '+ hpdiagVer),
              port:hpdsPort);
  exit(0);
}
exit(0);
