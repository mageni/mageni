###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zkteco_zkbiosecurity_detect.nasl 10891 2018-08-10 12:51:28Z cfischer $
#
# ZKTeco ZKBioSecurity Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809334");
  script_version("$Revision: 10891 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:51:28 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-10-06 14:17:14 +0530 (Thu, 06 Oct 2016)");
  script_name("ZKTeco ZKBioSecurity Detection");
  script_tag(name:"summary", value:"Detects the installed version of
  ZKTeco ZKBioSecurity.

  This script sends HTTP GET request and try to ensure the presence of
  ZKTeco ZKBioSecurity.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8088);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

zktPort = get_http_port(default:8088);

rcvRes = http_get_cache(item:"/", port:zktPort);

if('<title>ZKBioSecurity</title>' >< rcvRes && 'password' >< rcvRes)
{
    install = "/";
    version = "unknown";

    set_kb_item(name:"ZKTeco/ZKBioSecurity/Installed", value:TRUE);

    ## Created new cpe
    cpe = "cpe:/a:zkteco:zkbiosecurity";

    register_product(cpe:cpe, location:install, port:zktPort);

    log_message(data:build_detection_report(app:"ZKteco ZKBioSecurity",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version),
                                            port:zktPort);
  }

exit(0);
