###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_projectsend_remote_detect.nasl 10899 2018-08-10 13:49:35Z cfischer $
#
# ProjectSend Remote Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.807549");
  script_version("$Revision: 10899 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:49:35 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-04-19 11:50:28 +0530 (Tue, 19 Apr 2016)");
  script_name("ProjectSend Remote Version Detection");

  script_tag(name:"summary", value:"Detection of ProjectSend web application.

  This script sends HTTP GET request and checks for the presence of the
  application, and sets the result in KB.");

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
include("http_keepalive.inc");
include("host_details.inc");

pjtPort = get_http_port(default:80);
if(!can_host_php(port:pjtPort)){
  exit(0);
}

foreach dir(make_list_unique( "/", "/ProjectSend",  "/project" , cgi_dirs(port:pjtPort))) {

  install = dir;
  if( dir == "/") dir = "";

  url = dir + "/index.php";

  rcvRes = http_get_cache(item:url, port:pjtPort);

  if(rcvRes =~ "Provided by.*>ProjectSend.*Free software" &&
     '<title>Log in' >< rcvRes && '>Username' >< rcvRes &&
     '>Password' >< rcvRes)
  {
    version = "unknown";

    set_kb_item(name:"www/" + pjtPort + install, value:version);
    set_kb_item(name:"ProjectSend/Installed", value:TRUE);

    cpe= "cpe:/a:projectsend:projectsend";

    register_product( cpe:cpe, location:install, port:pjtPort );

    log_message(data:build_detection_report(app:"ProjectSend",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version),
                                            port:pjtPort);
  }
}

exit(0);
