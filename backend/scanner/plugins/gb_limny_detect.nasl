###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_limny_detect.nasl 10891 2018-08-10 12:51:28Z cfischer $
#
# Limny Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800295");
  script_version("$Revision: 10891 $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:51:28 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-03-02 12:02:59 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Limny Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Limny.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");


  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

limPort = get_http_port(default:80);

if( ! can_host_php( port:limPort ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/limny", "/limny/upload", cgi_dirs(port:limPort ) ) ) {

  rep_dir = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item:dir + "/index.php", port:limPort );

  if("Limny" >< rcvRes)
  {
    limVer = eregmatch(pattern:"Limny ([0-9.]+)" , string:rcvRes);

    if(limVer[1]){
      version = limVer[1];
    } else {
      version = "Unknown";
    }

    tmp_version = version + " under " + rep_dir;
    set_kb_item(name:"www/" + limPort + "/Limny", value:tmp_version);
    set_kb_item(name:"limny/installed",value:TRUE);

    log_message(data:"Limny version " + version + " running at location "
                 + rep_dir + " was detected on the host");

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:limny:limny:");
    if(!cpe)
       cpe = 'cpe:/a:limny:limny';

    register_product(cpe:cpe, location:rep_dir, port:limPort);

    log_message(data: build_detection_report(app:"Limny", version:version,
                                             install:rep_dir, cpe:cpe,
                                             concluded: limVer[0]),
                                             port:limPort);

  }
}

exit(0);