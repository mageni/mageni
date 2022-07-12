###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ba_systems_web_detect.nasl 9996 2018-05-29 07:18:44Z cfischer $
#
# Building Automation Systems BAS-Device Web Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.812371");
  script_version("$Revision: 9996 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-05-29 09:18:44 +0200 (Tue, 29 May 2018) $");
  script_tag(name:"creation_date", value:"2018-01-03 10:21:46 +0530 (Wed, 03 Jan 2018)");
  script_name("Building Automation Systems BAS-Device Web Detection");

  script_tag(name:"summary", value:"Detection of running version of
  Building Automation System device.

  This script sends HTTP GET request and try to ensure the presence of
  Building Automation System devices.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

basPort = get_http_port(default:80);

rcvRes = http_get_cache(port:basPort, item:"/");
if(rcvRes =~ "Server: BAS([0-9A-Z]+) HTTPserv:00002")
{
  basVer = "Unknown";
  set_kb_item(name:"BAS/Device/Installed", value:TRUE);
  model = eregmatch(pattern:" BAS([0-9A-Z]+) ", string:rcvRes);
  if(model[1])
  {
    set_kb_item(name:"BAS/Device/Model", value:model[1]);
    Model = model[1];
  } else {
    Model = "Unknown";
  }

  cpe = 'cpe:/h:building_automation_systems:bas';

  register_product(cpe:cpe, location:"/", port:basPort);

  log_message(data: build_detection_report(app: "Building Automation Systems BAS-Device",
                                           version: basVer,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: "BAS Device Version:" + basVer + ", Model:" + Model),
                                           port: basPort);
}

exit(0);
