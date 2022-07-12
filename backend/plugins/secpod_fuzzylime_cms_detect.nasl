###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_fuzzylime_cms_detect.nasl 10913 2018-08-10 15:35:20Z cfischer $
#
# Fuzzylime(cms) Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900583");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10913 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:35:20 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Fuzzylime(cms) Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of Fuzzylime(cms)
  and sets the version in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

cmsPort = get_http_port(default:80);

if( !can_host_php( port:cmsPort ) ) exit( 0 );

foreach dir (make_list_unique("/cms", "/", "/docs", "/fuzzylime", cgi_dirs(port:cmsPort)))
{

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:cmsPort);

  if("fuzzylime (cms)" ><rcvRes)
  {

    version = "unknown";

    sndReq = http_get(item: dir + "/admin/includes/ver.inc.php", port:cmsPort);
    rcvRes = http_keepalive_send_recv(port:cmsPort, data:sndReq);
    if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
    {
      cmsVer = egrep(pattern:"^([0-9]\.[0-9]+)", string:rcvRes);
      cmsVer = eregmatch(pattern:"([0-9.]+[a-z]?)", string:cmsVer);
    }
    else
    {
      sndReq = http_get(item: dir + "/docs/readme.txt", port:cmsPort);
      rcvRes = http_keepalive_send_recv(port:cmsPort, data:sndReq);
      if("fuzzylime (cms)" >< rcvRes){
        cmsVer = eregmatch(pattern:"v([0-9.]+)", string:rcvRes);
      }
    }
    if(cmsVer[1] != NULL) version = cmsVer[1];

    tmp_version = version + " under " + install;
    set_kb_item(name:"www/"+ cmsPort + "/Fuzzylime(cms)", value:tmp_version);
    set_kb_item(name:"fuzzylimecms/installed", value:TRUE);

    cpe = build_cpe(value:version, exp:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", base:"cpe:/a:fuzzylime:fuzzylime_cms:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:fuzzylime:fuzzylime_cms';

    register_product( cpe:cpe, location:install, port:cmsPort );

    log_message( data: build_detection_report( app:"Fuzzylime(cms)",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded:cmsVer[0]),
                                               port:cmsPort);

  }
}