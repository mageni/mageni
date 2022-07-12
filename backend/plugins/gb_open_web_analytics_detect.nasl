###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_web_analytics_detect.nasl 10898 2018-08-10 13:38:13Z cfischer $
#
# Open Web Analytics Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803794");
  script_version("$Revision: 10898 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:38:13 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2014-01-21 13:04:26 +0530 (Tue, 21 Jan 2014)");
  script_name("Open Web Analytics Version Detection");

  script_tag(name:"summary", value:"Detection of Open Web Analytics version.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

owaPort = get_http_port(default:80);

if(!can_host_php(port:owaPort)) exit(0);

foreach dir (make_list_unique("/", "/owa", "/analytics", cgi_dirs(port:owaPort))) {

  install = dir;
  if(dir == "/") dir = "";

  owaReq = http_get(item:dir + "/index.php?owa_do=base.loginForm",
                    port:owaPort);
  owaRes = http_keepalive_send_recv(port:owaPort, data:owaReq);

  if("Open Web Analytics</" >< owaRes) {
    ver = "unknown";

    owaVer = eregmatch(pattern:"v: ([0-9.]+)([a-zA-Z0-9.]+)?", string:owaRes);
    if(owaVer[1] != NULL) {
      if(owaVer[2] == NULL) {
        ver =  owaVer[1];
      } else
        ver = owaVer[1] + "." + owaVer[2] ;
    }

    set_kb_item(name:"www/" + owaPort + "/OWA", value: ver + " under " + install);
    set_kb_item(name:"OpenWebAnalytics/installed",value:TRUE);

    cpe = build_cpe(value:ver, exp:"^([0-9.]+)([a-zA-Z0-9.]+)?", base:"cpe:/a:openwebanalytics:open_web_analytics:");
    if(!cpe)
      cpe = 'cpe:/a:openwebanalytics:open_web_analytics';

    register_product(cpe:cpe, location: install, port:owaPort);
    log_message(data: build_detection_report(app:"Open Web Analytics",
                                             version:ver,
                                             install:install,
                                             cpe:cpe,
                                             concluded:owaVer[0]),
                                             port:owaPort);
  }
}

exit(0);
