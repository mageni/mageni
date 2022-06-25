###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_achievo_detect.nasl 10901 2018-08-10 14:09:57Z cfischer $
#
# Achievo Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.807645");
  script_version("$Revision: 10901 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:09:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-04-06 16:25:00 +0530 (Wed, 06 Apr 2016)");
  script_name("Achievo Detection");

  script_tag(name:"summary", value:"Detection of Achievo application.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

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

achPort = get_http_port(default:80);

if(!can_host_php(port:achPort)) exit(0);

foreach dir(make_list_unique("/", "/achievo", "/cms",  cgi_dirs(port:achPort)))
{
  install = dir;
  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:achPort);

  if('<title>Achievo</title>' >< rcvRes && 'login' >< rcvRes)
  {
    version = "unknown";

    set_kb_item(name:"www/" + achPort + "/achievo", value:version);
    set_kb_item(name:"Achievo/Installed", value:TRUE);

    cpe = "cpe:/a:achievo:achievo";

    register_product(cpe:cpe, location:install, port:achPort);

    log_message( data:build_detection_report( app:"Achievo",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version),
                                              port:achPort);
  }
}
exit(0);
