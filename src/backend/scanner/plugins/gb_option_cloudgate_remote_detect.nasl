###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_option_cloudgate_remote_detect.nasl 10898 2018-08-10 13:38:13Z cfischer $
#
# Option CloudGate Remote Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.808245");
  script_version("$Revision: 10898 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:38:13 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-07-04 17:44:06 +0530 (Mon, 04 Jul 2016)");
  script_name("Option CloudGate Remote Version Detection");
  script_tag(name:"summary", value:"Detects the installed version of
  Option CloudGate.

  This script sends HTTP GET request and try to detect the presence of
  Option CloudGate from the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

cloudPort = get_http_port(default:80);

rcvRes = http_get_cache(item:"/", port:cloudPort);

if('<title>CloudGate</title>' >< rcvRes && 'Powered by Cloudgate' >< rcvRes &&
  'username' >< rcvRes && 'password' >< rcvRes)
{
  cloudVer = "Unknown";

  set_kb_item(name:"Option/CloudGate/Installed", value:TRUE);

  ## created new cpe for this product
  cpe = "cpe:/o:option:cloudgate";

  register_product(cpe:cpe, location:"/", port:cloudPort);

  log_message(data: build_detection_report(app: "Option CloudGate",
                                           version: cloudVer,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: cloudVer),
                                           port: cloudPort);
}
