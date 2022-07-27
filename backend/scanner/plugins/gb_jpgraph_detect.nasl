###############################################################################
# OpenVAS Vulnerability Test
#
# JpGraph Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
#This program is free software; you can redistribute it and/or modify
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
  script_oid("1.3.6.1.4.1.25623.1.0.800413");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-01-13 15:42:20 +0100 (Wed, 13 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("JpGraph Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the running JpGraph version and saves
  the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

jgphPort = get_http_port(default:80);

foreach path (make_list_unique("/", "/jpgraph", "/jpgraph/docportal", cgi_dirs(port:jgphPort)))
{

  install = path;
  if( path == "/" ) path = "";

  rcvRes = http_get_cache(item: path + "/index.html", port:jgphPort);

  if("JpGraph" >< rcvRes)
  {

    version = "unknown";

    sndReq = http_get(item: path + "/../VERSION", port:jgphPort);
    rcvRes = http_keepalive_send_recv(port:jgphPort, data:sndReq, bodyonly:1);

    jgphVer = eregmatch(pattern:"v([0-9.]+)",string:rcvRes);
    if(jgphVer[1] != NULL) version = jgphVer[1];

    tmp_version = version + " under " + install;
    set_kb_item(name:"www/" + jgphPort + "/JpGraph", value:tmp_version);
    set_kb_item(name:"jpgraph/detected", value:TRUE);

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:aditus:jpgraph:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:aditus:jpgraph';

    register_product( cpe:cpe, location:install, port:jgphPort );

    log_message( data: build_detection_report( app:"Jp Graph",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded:jgphVer[0]),
                                               port:jgphPort);

  }
}
