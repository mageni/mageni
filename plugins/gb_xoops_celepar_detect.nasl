###############################################################################
# OpenVAS Vulnerability Test
#
# Xoops Celepar Version Detection
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the gnu general public license version 2
# (or any later version), as published by the free software foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.801152");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)");
  script_name("Xoops Celepar Version Detection");
  script_tag(name:"cvss_base", value:"0.0");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script is detects the installed version of Xoops Celepar
  and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

xoopsPort = get_http_port(default:80);
if(!can_host_php(port:xoopsPort)) exit(0);

foreach dir (make_list_unique("/xoopscelepar", "/" , cgi_dirs(port:xoopsPort))) {

  install = dir;
  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:xoopsPort);

  if(rcvRes =~ "HTTP/1\.[01] 200" && ">XOOPS Site" >< rcvRes) {

    version = "unknown";

    celeparVer = eregmatch(pattern:">Powered by XOOPS ([0-9.]+)", string:rcvRes);

    if(celeparVer[1] != NULL) {
      version = celeparVer[1];
    }

    tmp_version = version + " under " + install;
    set_kb_item(name:"www/" + xoopsPort + "/XoopsCelepar", value:tmp_version);
    set_kb_item(name:"xoops_celepar/detected", value:TRUE);

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:alexandre_amaral:xoops_celepar:");
    if(!cpe)
      cpe = 'cpe:/a:alexandre_amaral:xoops_celepar';

    register_product(cpe:cpe, location: install, port:xoopsPort);
    log_message(data: build_detection_report(app:"Xoops Celepar",
                                             version:version,
                                             install:install,
                                             cpe:cpe,
                                             concluded:celeparVer[0]),
                                             port:xoopsPort);

    exit(0);
  }
}
