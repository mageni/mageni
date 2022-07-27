##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_web_gateway_detect.nasl 10891 2018-08-10 12:51:28Z cfischer $
#
# McAfee Web Gateway (MWG) Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804419");
  script_version("$Revision: 10891 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:51:28 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2014-04-08 13:04:12 +0530 (Tue, 08 Apr 2014)");
  script_name("McAfee Web Gateway (MWG) Version Detection");

  script_tag(name:"summary", value:"Detection of McAfee Web Gateway (MWG).

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("McAfee_Web_Gateway/banner");
  script_require_ports("Services/www", 8080);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");


mwgPort = get_http_port(default:8080);

mwgBanner = get_http_banner(port:mwgPort);

if("McAfee Web Gateway" >!< mwgBanner) exit(0);

version = "unknown";

mwgVer = eregmatch(pattern:"McAfee Web Gateway ([0-9.]+)", string:mwgBanner);
if(mwgVer[1]) {
  version = mwgVer[1];
}

set_kb_item(name:"www/" + mwgPort + "/McAfee/Web/Gateway", value:version);
set_kb_item(name:"McAfee/Web/Gateway/installed", value:TRUE);

cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:mcafee:web_gateway:");
if(isnull(cpe))
  cpe = 'cpe:/a:mcafee:web_gateway';

register_product(cpe:cpe, location:mwgPort + '/tcp', port:mwgPort);

log_message(data: build_detection_report(app:"McAfee Web Gateway",
                                         version:version,
                                         install:mwgPort + '/tcp',
                                         cpe:cpe,
                                         concluded: mwgVer[0]),
                                         port:mwgPort);
exit(0);
