###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asbru_web_content_mgnt_sys_detect.nasl 11020 2018-08-17 07:35:00Z cfischer $
#
# Asbru Web Content Management System Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.807657");
  script_version("$Revision: 11020 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 09:35:00 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-04-12 17:30:16 +0530 (Tue, 12 Apr 2016)");
  script_name("Asbru Web Content Management System Detection");

  script_tag(name:"summary", value:"Detection of Asbru Web Content
  Management System.

  This script sends HTTPS GET request and checks for the presence of
  the application.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

asbPort = get_http_port(default:443);

foreach dir(make_list_unique( "/", "/asbru",  "/wcm" , cgi_dirs(port:asbPort)))
{
  install = dir;
  if( dir == "/") dir = "";

  url = dir + "/index.jsp";
  asbRes = http_get_cache(port:asbPort, item:url);

  if(asbRes =~ '>Asbru Web Content Management.*<' && 'www.asbrusoft.com' >< asbRes)
  {
    version = "unknown";

    set_kb_item(name:"www/" + asbPort + install, value:version);
    set_kb_item( name:"Asbru/Installed", value:TRUE);

    cpe = "cpe:/a:asbru_web_content_management_system:asbru";
    register_product(cpe:cpe, location:install, port:asbPort);

    log_message( data:build_detection_report( app:"Asbru Web Content Management System",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version),
                                              port:asbPort);
  }
}
exit( 0 );
