###############################################################################
# OpenVAS Vulnerability Test
# $Id: cutenews_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# CuteNews Detection
#
# Authors:
# Michael Meyer
#
# Updated to detect UTF-8 CuteNews
#  - By Antu Sanadi <santu@secpod.com> On 2009-12-05 #5990
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100105");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2009-04-05 20:39:41 +0200 (Sun, 05 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("CuteNews Detection");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running CuteNews, a powerful and easy to use news management
system that uses flat files to store its database");

  script_xref(name:"URL", value:"http://cutephp.com/cutenews/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir (make_list_unique( "/cutenews", "/utf-8", "/news", "/", cgi_dirs(port: port))) {
  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );
  if( buf == NULL )continue;

  # CuteNews
  if (egrep(pattern: "Powered by <a [^>]+>CuteNews", string: buf, icase: TRUE) ||
      "title>Please Login / CuteNews</title>" >< buf) {
    vers = "unknown";

    set_kb_item(name: "cutenews/installed", value: TRUE);

    version = eregmatch(string: buf, pattern: "Powered by <a [^>]+>CuteNews v*([0-9.]+)</a>",icase:TRUE);
    if (!isnull(version[1]))
      vers=version[1];
    else {
      version = eregmatch(string: buf, pattern: ">CuteNews v\.([0-9.]+)");
      if (!isnull(version[1]))
        vers = version[1];
    }

    cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:cutephp:cutenews:");
    if (!cpe)
      cpe = "cpe:/a:cutephp:cutenews";

    register_product(cpe: cpe, location: install, port: port);

    log_message(data: build_detection_report(app: "CuteNews", version: vers, install: install, cpe: cpe,
                                             concluded: version[0]),
                port: port);
    exit(0);
  }
  # UTF-8 CuteNews
  else if ("<title>UTF-8 CuteNews</title>" >< buf) {
    set_kb_item(name: "cutenews/installed", value: TRUE);
    set_kb_item(name: "cutenews/utf-8", value: TRUE);

    version = eregmatch(string: buf, pattern: "UTF-8 CuteNews (([0-9.]+)([a-z]+)?)", icase:TRUE);
    if (!isnull(version[1]))
      vers=version[1];

    cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:cutephp:cutenews:");
    if (!cpe)
      cpe = "cpe:/a:cutephp:cutenews";

    register_product(cpe: cpe, location: install, port: port);

    log_message(data: build_detection_report(app: "UTF-8 CuteNews", version: vers, install: install, cpe: cpe,
                                             concluded: version[0]),
                port: port);
    exit(0);
  }
}

exit(0);
