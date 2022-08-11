###############################################################################
# OpenVAS Vulnerability Test
#
# Sun Java System Portal Server Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801247");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-08-06 17:02:44 +0200 (Fri, 06 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Sun Java System Portal Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the running Sun Java System Portal Server version
  and saves the result in KB.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Sun Java System Portal Server Version Detection";

port = get_http_port(default:8080);

sndReq = http_get(item:"/psconsole/faces/common/ProductVersion.jsp", port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

if(">Portal Server Product Version<" >< rcvRes && "Sun Microsystems" >< rcvRes)
{
  ver = eregmatch(pattern:">Version ([0-9.]+)<", string:rcvRes);

  if(ver[1] != NULL)
  {
    set_kb_item(name:"www/" + port + "/Sun/Java/Portal/Server", value:ver[1]);
    set_kb_item(name:"sun/java/portal/server/detected", value:TRUE);
    log_message(data:"Sun Java System Portal Server version " + ver[1] +
                       " was detected on the host", port:port);

    cpe = build_cpe(value:ver[1], exp:"^([0-9.]+)", base:"cpe:/a:sun:java_system_portal_server:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

  }
}
