###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samsung_syncthru_web_service_detect.nasl 13650 2019-02-14 06:48:40Z cfischer $
#
# Samsung Syncthru Web Service Remote Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813744");
  script_version("$Revision: 13650 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 07:48:40 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-08-06 17:37:28 +0530 (Mon, 06 Aug 2018)");
  script_name("Samsung Syncthru Web Service Remote Detection");

  script_tag(name:"summary", value:"Detection of presence of Samsung Syncthru
  Web Service.

  The script sends a HTTP GET connection request to the server and attempts
  to determine if the remote host runs Samsung Syncthru Web Service from
  the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://www.samsungsetup.com/ts/manual/Samsung%20M2070%20Series/English/manual/CHDIBFBI.htm");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

samPort = get_http_port(default:80);
res = http_get_cache(port:samPort, item:"/sws/index.sws");

if("<title>SyncThru Web Service</title>" >< res && res =~ "Copyright.*Samsung Electronics"
   && "Login" >< res)
{
  version = "unknown";
  install = "/";
  set_kb_item(name:"Samsung/SyncThru/Web/Service/installed", value:TRUE);

  req = http_get_req( port:samPort, url:"/Information/firmware_version.htm");
  res = http_keepalive_send_recv( port:samPort, data:req );

  if(res =~ "HTTP/1.. 200 OK" && res =~ "<title>SWS.*Information.*Firmware.Version.</title>")
  {
    vers = eregmatch( pattern:"Main Firmware Version.*(V[0-9A-Z._]+).*Network Firmware Version.*(V[0-9A-Z().]+).*Engine Firmware Version", string:res);
    if(vers[1] && vers[2])
    {
      mainVer = vers[1];
      netVer = vers[2];

      ## Lot of details available. Not sure if Version information of
      ## Samsung Syncthru Web Service is available. Currently Setting Main Firmware Version as version.
      version = mainVer;
      set_kb_item(name:"Samsung/SWS/NetVer", value:netVer);
    }
  }
  ## Created new cpe
  cpe = "cpe:/a:samsung:syncthru_web_service:";

  register_product(cpe:cpe, location:install, port:samPort);

  log_message(data:build_detection_report(app:"Samsung SyncThru Web Service",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:"Main Firmware Version " + version + " with Network Firmware Version " + netVer),
                                          port:samPort);
}

exit(0);