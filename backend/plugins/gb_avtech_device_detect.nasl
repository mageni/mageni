###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avtech_device_detect.nasl 13472 2019-02-05 13:34:23Z tpassfeld $
#
# AVTECH Device Detection
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809066");
  script_version("$Revision: 13472 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 14:34:23 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-10-18 11:30:44 +0530 (Tue, 18 Oct 2016)");
  script_name("AVTECH Device Detection");

  script_tag(name:"summary", value:"Detection of AVTECH Device.

  This script sends HTTP GET request and try to ensure the presence of
  AVTECH Device from the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Avtech/banner");

  exit(0);
}


include("http_func.inc");

include("host_details.inc");


avPort = get_http_port(default: 80);

banner = get_http_banner(port:avPort);

if(banner !~ "HTTP/1.. 200 OK" || banner !~ "Server:.*Avtech"){
  exit(0);
}

avVer = "Unknown";

set_kb_item(name:"AVTECH/Device/Installed", value:TRUE);

## Created new cpe
cpe = "cpe:/o:avtech:avtech_device";

register_product(cpe:cpe, location:"/", port:avPort);

log_message(data: build_detection_report(app: "AVTECH Device",
                                           version: avVer,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: avVer),
                                           port: avPort);
exit(0);
