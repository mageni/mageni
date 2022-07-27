###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_jrun_detect.nasl 11028 2018-08-17 09:26:08Z cfischer $
#
# Sun Adobe JRun Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900822");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11028 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 11:26:08 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Sun Adobe JRun Version Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of Adobe JRun and
  sets the version in KB.");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

jrunPort = get_http_port(default:8000);

rcvRes = http_get_cache(item:"/", port:jrunPort);

if(egrep(pattern:"Server: JRun Web Server", string:rcvRes) &&
   egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
{
  jrunVer = eregmatch(pattern:">Version ([0-9.]+)", string:rcvRes);

  if(jrunVer[1] != NULL){
    set_kb_item(name:"/Adobe/JRun/Ver", value:jrunVer[1]);
    log_message(data:"Adobe JRun version " + jrunVer[1] +
                                      " was detected on the host");

    cpe = build_cpe(value: jrunVer[1], exp:"^([0-9.]+)",base:"cpe:/a:adobe:jrun:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe);

  }
}
