###############################################################################
# OpenVAS Vulnerability Test
# $Id: zabbix_web_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# ZABBIX Web Interface Detection
#
# Authors:
# Michael Meyer
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100405");
  script_version("$Revision: 11885 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2009-12-17 19:46:08 +0100 (Thu, 17 Dec 2009)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("ZABBIX Web Interface Detection");

  script_tag(name:"summary", value:"Detects the installed version of ZABBIX
 Web Interface.

 This script sends a connection request to the server and attempts to
 extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "zabbix_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

include("cpe.inc");
include("host_details.inc");

zbPort = get_http_port(default:80);
if(!can_host_php(port:zbPort))exit(0);

foreach dir( make_list_unique("/", "/zabbix", "/monitoring", cgi_dirs( port:zbPort ) ) ) {

  install = dir;
  if (dir == "/") dir = "";

  url = string(dir, "/index.php");
  buf = http_get_cache(item:url, port:zbPort);
  if( buf == NULL )continue;

  if((egrep(pattern: "index.php\?login=1", string: buf, icase: TRUE) &&
      egrep(pattern: "SIA Zabbix", string: buf)) ||
     (buf =~"<title>(.*)?Zabbix</title>" && "Zabbix SIA" >< buf))
  {
    zbVer = string("unknown");
    version = eregmatch(string: buf, pattern: "Zabbix([&nbsp; ]+)([0-9.]+)",icase:TRUE);
    if (!isnull(version[2])){
      zbVer=chomp(version[2]);
    }
    else {
      version = eregmatch(string: buf, pattern: "jsLoader.php\?ver=([0-9.]+)");
      if (!isnull(version[1]))
        zbVer = version[1];
    }

    set_kb_item(name: string("www/", zbPort, "/zabbix_client"), value: string(zbVer," under ",install));
    set_kb_item(name:"Zabbix/installed", value:TRUE);
    set_kb_item(name:"Zabbix/Web/installed", value:TRUE);

    cpe = build_cpe(value:zbVer, exp:"^([0-9.]+)", base:"cpe:/a:zabbix:zabbix:");
    if(!cpe)
      cpe = 'cpe:/a:zabbix:zabbix';

    register_product(cpe:cpe, location:install, port:zbPort, service:"www" );
    log_message(data: build_detection_report(app:"Zabbix",
                                             version:zbVer,
                                             install:install,
                                             cpe:cpe,
                                             concluded: version[0]),
                                             port:zbPort);
  }
}

exit(0);
