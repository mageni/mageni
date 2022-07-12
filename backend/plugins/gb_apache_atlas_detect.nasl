###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_atlas_detect.nasl 11321 2018-09-11 10:05:53Z cfischer $
#
# Apache Atlas Version Detection
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.112030");
  script_version("$Revision: 11321 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-11 12:05:53 +0200 (Tue, 11 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-08-31 13:26:04 +0200 (Thu, 31 Aug 2017)");
  script_name("Apache Atlas Version Detection");
  script_tag(name:"summary", value:"Detection of installed version
  of Apache Atlas.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl", "find_service.nasl");
  script_require_ports("Services/www", 21000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:21000);

rcvRes = http_get_cache(port:port, item:"/#!/search");

if (rcvRes =~ "HTTP/1.. 200" && "<title>Apache Atlas</title>" >< rcvRes
    && "/modules/home/views/header.html" >< rcvRes)
{

  version = "unknown";

  set_kb_item( name:"Apache/Atlas/Installed", value:TRUE );

  req = http_get(port:port, item:"/api/atlas/admin/version");
  res = http_keepalive_send_recv(port:port, data:req);
  ver = eregmatch( pattern:'"Version":"([0-9.]+)[^"]+', string:res);
  if (!isnull(ver[1]))
  {
    version = ver[1];
    set_kb_item(name:"Apache/Atlas/version", value:version);
    url = "/api/atlas/admin/version";
  }

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:atlas:");
  if (!cpe)
    cpe = "cpe:/a:apache:atlas";

 register_product(cpe:cpe, location:"/", port:port);

 log_message(data:build_detection_report(app:"Apache Atlas",
                                          version:version,
                                          install:"/",
                                          cpe:cpe,
                                          concluded:ver[0],
                                          concludedUrl:url),
                                          port:port);
}
exit(0);
