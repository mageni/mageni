###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_geovision_ip_camera_remote_detect.nasl 11670 2018-09-28 09:04:03Z tpassfeld $
#
# Geovision Inc. IP Camera Remote Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.812758");
  script_version("$Revision: 11670 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 11:04:03 +0200 (Fri, 28 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-02-08 17:51:20 +0530 (Thu, 08 Feb 2018)");
  script_name("Geovision Inc. IP Camera Remote Detection");

  script_tag(name:"summary", value:"Detection of running version of Geovision
  Inc. IP Camera.

  This script sends HTTP GET request and try to ensure the presence of
  Geovision Inc. IP Camera.");

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
include("cpe.inc");

port = get_http_port(default: 80);
url = "/ssi.cgi/Login.htm";

res = http_get_cache(port: port, item: "/ssi.cgi/Login.htm");

if('document.write("<INPUT name=umd5' >< res || 'document.write("<INPUT name=pmd5' >< res) {

  version = "unknown";

  set_kb_item(name: "geovision/ip_camera/detected", value: TRUE);

  CPE = "cpe:/h:geovision:geovisionip_camera";

  conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "GeoVision IP Camera",
                          ver: version,
                          concluded: version,
                          base: CPE,
                          expr: '([0-9.]+)',
                          insloc: "/",
                          regPort: port,
                          conclUrl: conclUrl);
}

exit(0);
