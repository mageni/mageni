###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_sitescope_detect.nasl 10888 2018-08-10 12:08:02Z cfischer $
#
# HP SiteScope Version Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805284");
  script_version("$Revision: 10888 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:08:02 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-02-23 10:54:54 +0530 (Mon, 23 Feb 2015)");
  script_name("HP SiteScope Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  HP SiteScope.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("SiteScope/banner");
  script_require_ports("Services/www", 8080);
  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

hpPort = get_http_port(default:8080);

if(!banner = get_http_banner(port:hpPort)){
  exit(0);
}

if("Server: SiteScope" >< banner || banner =~ "Location: .*SiteScope")
{
  version = "unknown";

  dir = "/";

  set_kb_item(name:"hp/sitescope/installed", value:TRUE);

  hpVer = eregmatch(pattern:"Server: SiteScope/([^ ]+)", string:banner);
  if(!isnull(hpVer[1])){
    version = hpVer[1];
  }
  else
  {
    sndReq = http_get(item:"/SiteScope/", port:hpPort);
    rcvRes = http_keepalive_send_recv(port:hpPort, data:sndReq);

    if(">Login - SiteScope<"  >< rcvRes ||
       "HostedSiteScopeMessage.jsp?messageSeverity=" >< rcvRes)
    {
      dir = "/SiteScope/";

      hpVer = eregmatch(pattern:'header-login".*SiteScope ([0-9.]+).*>', string:rcvRes);
      if(!isnull(hpVer[1])){
        version = hpVer[1];
      }
    }
  }

  set_kb_item(name:"www/" + hpPort + "/hpsitescope", value:hpVer);

  cpe = build_cpe(value:version, exp:"([0-9.]+)", base:"cpe:/a:hp:sitescope:");
  if(isnull(cpe))
    cpe = "cpe:/a:hp:sitescope";

  register_product(cpe:cpe, location:dir, port:hpPort);
  log_message(data: build_detection_report(app:"HP SiteScope",
                                           version:version,
                                           install:dir,
                                           cpe:cpe,
                                           concluded:hpVer),
              port:hpPort);
  exit(0);
}
