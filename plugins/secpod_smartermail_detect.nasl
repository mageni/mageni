###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_smartermail_detect.nasl 11015 2018-08-17 06:31:19Z cfischer $
#
# SmarterMail Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated by: Antu Sanadi <santu@secpod.com>
# Updated according to new style.
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902258");
  script_version("$Revision: 11015 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-10-01 08:36:34 +0200 (Fri, 01 Oct 2010)");
  script_name("SmarterMail Version Detection");

  script_tag(name:"summary", value:"Detection of SmarterMail version.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 9998);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

smPort = get_http_port(default:9998);
if( ! can_host_asp( port:smPort ) ) exit( 0 );

SmRes = http_get_cache(item:"/Login.aspx", port:smPort);

if(">SmarterMail" >!< SmRes && ">SmarterMail Enterprise" >!< SmRes && ">SmarterMail Standard" >!< SmRes){
  exit(0);
}

version = "unknown";

ver = eregmatch(pattern:">SmarterMail [a-zA-Z]+ ([0-9.]+)<", string:SmRes);
if(ver[1]) version = ver[1];

set_kb_item(name:"SmarterMail/Ver", value:version);
set_kb_item(name:"SmarterMail/installed", value:TRUE);

cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:smartertools:smartermail:");
if(!cpe)
  cpe = 'cpe:/a:smartertools:smartermail';

register_product(cpe:cpe, location:"/", port:smPort);
log_message(data: build_detection_report(app:"SmarterMail", version:version,
                                         install:"/", cpe:cpe,
                                         concluded: ver[0]),
                                         port:smPort);

exit(0);