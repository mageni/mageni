###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_schneider_electric_pelco_sarix_ip_cam_detect.nasl 13584 2019-02-11 14:47:27Z tpassfeld $
#
# Schneider Electric Pelco Sarix IP Camera Remote Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.813064");
  script_version("$Revision: 13584 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 15:47:27 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-04-03 14:44:14 +0530 (Tue, 03 Apr 2018)");
  script_name("Schneider Electric Pelco Sarix IP Camera Remote Detection");

  script_tag(name:"summary", value:"Detection of presence of Schneider
  Electric Pelco Sarix IP Camera.

  The script sends a HTTP GET connection request to the server and attempts
  to determine if the remote host runs Electric Pelco Sarix IP Camera from
  the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

ipPort = get_http_port(default:80);

res = http_get_cache(port:ipPort, item:"/liveview");

if(res =~ "<span>[Ss]arix&[Tt]rade;</span>" && res =~ "<span>Copyright\s*&copy;\s*[0-9]+-[0-9]+,\s*[Pp][Ee][Ll][Cc][Oo]\s*&middot;"
  || "Sarix&trade;" >< res && 'tooltip.js"></script>' >< res && 'cookie.js"></script>' >< res)
{
  version = "unknown";
  install = "/";
  set_kb_item(name:"Schneider_Electric/Pelco_Sarix/IP_Camera/installed", value:TRUE);

  ## Created new cpe
  ## According to information from NVD, it varies according to firmware version
  cpe = "cpe:/a:schneider_electric:pelco_sarix_professional";

  register_product(cpe:cpe, location:install, port:ipPort);

  log_message(data:build_detection_report(app:"Schneider Electric Pelco Sarix IP Camera",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:version),
                                          port:ipPort);
  exit(0);
}
exit(0);
