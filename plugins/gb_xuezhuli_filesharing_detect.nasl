###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xuezhuli_filesharing_detect.nasl 10913 2018-08-10 15:35:20Z cfischer $
#
# XuezhuLi FileSharing Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.808175");
  script_version("$Revision: 10913 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:35:20 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-06-27 14:54:44 +0530 (Mon, 27 Jun 2016)");
  script_name("XuezhuLi FileSharing Detection");
  script_tag(name:"summary", value:"Detection of installed version
  of XuezhuLi FileSharing.

  This script sends HTTP GET request and try to check the presence of
  XuezhuLi FileSharing from the response.");

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

file_Port = get_http_port(default:80);
if(!can_host_php(port:file_Port)) exit(0);

foreach dir(make_list_unique("/", "/FileSharing-master", "/FileSharing",  cgi_dirs(port:file_Port)))
{
  install = dir;
  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:file_Port);

  if('<title>File Manager</title>' >< rcvRes && 'Username' >< rcvRes
      && '>login<' >< rcvRes && '>signup<' >< rcvRes)
  {
    version = "unknown";

    set_kb_item(name:"www/" + file_Port + install, value:version);
    set_kb_item(name:"XuezhuLi/FileSharing/Installed", value:TRUE);

    ## created new cpe
    cpe = "cpe:/a:xuezhuLi:xuezhuli_filesharing";

    register_product(cpe:cpe, location:install, port:file_Port);

    log_message( data:build_detection_report( app:"XuezhuLi FileSharing",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version),
                                              port:file_Port);
  }
}
exit(0);
