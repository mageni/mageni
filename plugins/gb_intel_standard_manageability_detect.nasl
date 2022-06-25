###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_intel_standard_manageability_detect.nasl 11408 2018-09-15 11:35:21Z cfischer $
#
# Intel Standard Manageability Remote Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810998");
  script_version("$Revision: 11408 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:35:21 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-05-05 15:39:37 +0530 (Fri, 05 May 2017)");
  script_name("Intel Standard Manageability Remote Detection");

  script_tag(name:"summary", value:"Detection of Intel Standard Manageability.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 16992, 16993);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

intPort = get_http_port(default:16992);

intRes = http_get_cache(port:intPort, item: "/logon.htm");

if('Server: Intel(R) Standard Manageability' >< intRes &&
   '<title>Intel&reg; Standard Manageability</title>' >< intRes)
{
  version = "unknown";
  ver = eregmatch(pattern:"Server: Intel\(R\) Standard Manageability ([0-9.]+)", string:intRes);
  if(ver[1]) version = ver[1];

  set_kb_item(name:"Intel/Standard/Manageability/Installed", value:TRUE);
  set_kb_item(name:"Intel/Standard/Manageability/version", value:version);

  cpe = build_cpe(value: version, exp:"^([0-9.]+)", base:"cpe:/h:intel:intel_standard_manageability:");
  if( ! cpe )
    cpe = "cpe:/h:intel:intel_standard_manageability";

  register_product(cpe:cpe, location:"/", port:intPort);

  log_message(data:build_detection_report( app:"Intel Standard Manageability",
                                           version:version,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:version),
                                           port:intPort);

}
exit(0);
