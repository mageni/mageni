###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dup_scount_enterprise_detect.nasl 11019 2018-08-17 07:20:12Z cfischer $
#
# Dup Scout Enterprise Version Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809064");
  script_version("$Revision: 11019 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 09:20:12 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-10-13 16:11:25 +0530 (Thu, 13 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Dup Scout Enterprise Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Dup Scout Enterprise.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("httpver.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);
res = http_get_cache(item:"/login", port:port);

if(">Dup Scout Enterprise" >< res &&
   ">User Name" >< res && ">Password" >< res)
{
  dupVer = eregmatch(pattern:">Dup Scout Enterprise v([0-9.]+)", string:res);
  if(dupVer[1]){
    dupVer = dupVer[1];
  } else {
    dupVer = "Unknown";
  }

  set_kb_item(name:"Dup/Scout/Enterprise/installed", value:TRUE);

  cpe = build_cpe(value:dupVer, exp:"([0-9.]+)", base:"cpe:/a:dup:dup_scout_enterprise:");
  if(isnull(cpe))
    cpe = "cpe:/a:dup:dup_scout_enterprise";

  register_product(cpe:cpe, location:"/", port:port);
  log_message(data: build_detection_report(app: "Dup Scout Enterprise",
                                           version:dupVer,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:dupVer),
                                           port:port);
}
exit(0);
