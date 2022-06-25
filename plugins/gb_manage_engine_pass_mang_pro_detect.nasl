###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manage_engine_pass_mang_pro_detect.nasl 11015 2018-08-17 06:31:19Z cfischer $
#
# ManageEngine Password Manager Version Detection
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805714");
  script_version("$Revision: 11015 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-07-07 15:16:06 +0530 (Tue, 07 Jul 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("ManageEngine Password Manager Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  ManageEngine Password Manager pro.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 7272);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

mePort = get_http_port(default:7272);

req = http_get(item:"/PassTrixMain.cc", port:mePort);
res = http_keepalive_send_recv(port:mePort, data:req);

if("<title>ManageEngine Password Manager Pro</title>" >< res && "PMP_User_Locale" >< res && "ZOHO Corp" >< res)
{
  meVer = eregmatch(pattern:"/themes/passtrix/V([0-9]+)", string:res);
  if(!meVer[1]){
   meVer = "Unknown";
  } else {
    meVer = meVer[1];
  }

  tmp_version = "Build version " + meVer ;

  set_kb_item(name:"www/" + mePort + "/", value:meVer);
  set_kb_item(name:"ManageEngine/Password_Manager/installed",value:TRUE);

  cpe = build_cpe(value:meVer, exp:"^([0-9]+)", base:"cpe:/a:manageengine:password_manager_pro:");
  if(isnull(cpe))
    cpe = "cpe:/a:manageengine:password_manager_pro";

  register_product(cpe:cpe, location:"/", port:mePort);
  log_message(data: build_detection_report(app:"ManageEngine Password Manager" ,
                                           version:meVer,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:tmp_version),
                                           port:mePort);
}

exit(0);
