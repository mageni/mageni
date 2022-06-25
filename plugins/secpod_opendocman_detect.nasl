##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opendocman_detect.nasl 10901 2018-08-10 14:09:57Z cfischer $
#
# OpenDocMan Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900884");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10901 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:09:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-10-29 07:53:15 +0100 (Thu, 29 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OpenDocMan Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed OpenDocMan version and sets
  the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

docmanPort = get_http_port(default:80);

if(!can_host_php(port:docmanPort)) exit(0);

foreach dir (make_list_unique("/", "/docman", "/opendocman", cgi_dirs(port:docmanPort))) {

  install = dir;
  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:docmanPort);

  if("Welcome to OpenDocMan" >!< rcvRes) {
    rcvRes = http_get_cache(item: dir + "/admin.php", port:docmanPort);
  }

  if("Welcome to OpenDocMan" >< rcvRes &&
     egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes)) {

    version = "unknown";

    docmanVer = eregmatch(pattern:"OpenDocMan v([0-9.]+)([a-z]+[0-9])?",
                          string:rcvRes);
    if(docmanVer[1]) {
      if(docmanVer[2]) {
        version = docmanVer[1] + "." + docmanVer[2];
      } else {
        version = docmanVer[1];
      }
    }

    tmp_version = version + " under " + install;
    set_kb_item(name:"www/"+ docmanPort + "/OpenDocMan",
                value:tmp_version);
    set_kb_item( name:"OpenDocMan/installed", value:TRUE );

    cpe = build_cpe(value:docmanVer, exp:"^([0-9.]+)", base:"cpe:/a:opendocman:opendocman:");
    if(isnull(cpe))
        cpe = 'cpe:/a:opendocman:opendocman';

    register_product( cpe:cpe, location:install, port:docmanPort );
    log_message( data:build_detection_report( app:"OpenDocMan",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded: docmanVer[0] ),
                 port: docmanPort);

  }
}
