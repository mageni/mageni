###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_master_ip_camera01_detect.nasl 12754 2018-12-11 09:39:53Z cfischer $
#
# Master IP Camera Remote Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.812657");
  script_version("$Revision: 12754 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-11 10:39:53 +0100 (Tue, 11 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-01-22 12:19:43 +0530 (Mon, 22 Jan 2018)");
  script_name("Master IP Camera Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("thttpd/banner");

  script_tag(name:"summary", value:"This script tries to detect a Master IP Camera
  and its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:80);
res = http_get_cache(item:"/web/index.html", port:port);

if(res =~ "Server:.thttpd" && ("<title>ipCAM<" >< res || "<title>Camera<" >< res) &&
   "cgi-bin/hi3510" >< res && ">OCX" >< res)
{

  version = "unknown";
  set_kb_item(name:"MasterIP/Camera/Detected", value:TRUE);

  ## creating new cpe for this product
  cpe = "cpe:/h:masterip:masterip_camera";

  register_product(cpe:cpe, location:"/", port:port, service:"www");

  log_message(data:build_detection_report(app:"Master IP Camera",
                                          version:version,
                                          install:"/",
                                          cpe:cpe),
                                          port:port);
}

exit(0);