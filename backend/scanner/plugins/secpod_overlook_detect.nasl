###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_overlook_detect.nasl 11823 2018-10-10 13:57:02Z asteins $
#
# OPEN IT OverLook Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902513");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11823 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 15:57:02 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-05-09 15:38:03 +0200 (Mon, 09 May 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OPEN IT OverLook Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends an HTTP GET request to figure out whether OverLook is running on the remote host, and, if so, which version is installed.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);

foreach dir (make_list("/overlook"))
{
  install = dir;
  if (dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/src/login.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  if(">OverLook by Open IT<" >< rcvRes)
  {
    set_kb_item(name:"overlook/detected", value:TRUE);
    version = "unknown";
    version_url = dir + "/README";

    sndReq = http_get(item:version_url, port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

    ver_match = eregmatch(pattern:"Version \.+ ([0-9.]+)", string:rcvRes);
    if(ver_match[1])
    {
      version = ver_match[1];
      concluded_url = report_vuln_url(port:port, url:version_url, url_only:TRUE);
    }

    register_and_report_cpe(app:"OverLook", ver:version, concluded:ver_match[0], base:"cpe:/a:openit:overlook:", expr:"^([0-9.]+)", insloc:install, regPort:port, conclUrl:concluded_url);

    exit(0);
  }
}
