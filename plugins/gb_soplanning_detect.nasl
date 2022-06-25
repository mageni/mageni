###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_soplanning_detect.nasl 11396 2018-09-14 16:36:30Z cfischer $
#
# Simple Online Planning Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.112034");
  script_version("$Revision: 11396 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-14 18:36:30 +0200 (Fri, 14 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-09-04 12:33:04 +0200 (Mon, 04 Sep 2017)");
  script_name("Simple Online Planning Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl", "find_service.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed version
  of Simple Online Planning.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);

foreach dir(make_list_unique("/", "/SOPlanning/www", cgi_dirs(port:port))) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(port:port, item:dir + "/");

  if (rcvRes =~ "^HTTP/1\.[01] 200" && ('<title>SoPlanning</title>' >< rcvRes
      || '<span class="soplanning_index_title2">Simple Online Planning</span>' >< rcvRes
      || '<a target="_blank" href="http://www.soplanning.org">www.soplanning.org</a>' >< rcvRes
      || '<meta name="reply-to" content="support@soplanning.org" />' >< rcvRes
      || '<meta name="email" content="support@soplanning.org" />' >< rcvRes
      || '<meta name="Identifier-URL" content="http://www.soplanning.org" />' >< rcvRes))
  {
    version = "unknown";

    set_kb_item( name:"SOPlanning/Installed", value:TRUE );

    ver = eregmatch( pattern:'<small>v([0-9.]+)</small>', string:rcvRes);
    if (!isnull(ver[1])) version = ver[1];

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:soplanning:soplanning:");
    if (!cpe) cpe = "cpe:/a:soplanning:soplanning";

    register_product(cpe:cpe, location:install, port:port);

    log_message(data:build_detection_report(app:"SOPlanning",
        version:version,
        install:install,
        cpe:cpe,
        concluded:ver[0]),
      port:port);
  }
}
exit(0);
