###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_web_app_test_suite_detect.nasl 11418 2018-09-17 05:57:41Z cfischer $
#
# Oracle Application Testing Suite Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809730");
  script_version("$Revision: 11418 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 07:57:41 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-11-25 10:47:18 +0530 (Fri, 25 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Oracle Application Testing Suite Detection");
  script_tag(name:"summary", value:"Detects the installed version of
  Oracle Application Testing Suite.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8088);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

oatPort = get_http_port(default:8088);

sndReq = http_get(item:"/olt/Login.do", port:oatPort);
rcvRes = http_keepalive_send_recv(port:oatPort, data:sndReq);

if(rcvRes && ">Oracle Application Testing Suite Service Home Page<" >< rcvRes
   && "Login<" >< rcvRes)
{
  oatVer = eregmatch(pattern:"Version:&nbsp;([0-9.]+)( build ([0-9.]+))?", string:rcvRes);

  if(oatVer[1] && oatVer[2])
  {
    app_Ver = oatVer[1] + ' build ' + oatVer[3];
    version = oatVer[1] + 'build' + oatVer[3];
    set_kb_item(name:"Oracle/Application/Testing/Suite/build",value:oatVer[3]);
  }
  else if(oatVer[1]){
    version = oatVer[1];
  }
  else {
    version = "unknown";
  }

  set_kb_item(name:"Oracle/Application/Testing/Suite/installed", value:TRUE);

  ## Created new cpe
  cpe = build_cpe(value:version, exp:"([0-9.]+)(build.[0-9.]+)?", base:"cpe:/a:oracle:application_testing_suite:");
  if(isnull(cpe))
    cpe = "cpe:/a:oracle:application_testing_suite";

  register_product(cpe:cpe, location:"/", port:oatPort);
  log_message(data: build_detection_report(app: "Oracle Application Testing Suite",
                                           version:app_Ver,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:app_Ver),
                                           port:oatPort);
  exit(0);
}
exit(0);
