###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_smarterstats_detect.nasl 9153 2018-03-21 09:31:39Z asteins $
#
# SmarterStats Detection
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108255");
  script_version("$Revision: 9153 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-21 10:31:39 +0100 (Wed, 21 Mar 2018) $");
  script_tag(name:"creation_date", value:"2017-10-18 10:31:53 +0200 (Wed, 18 Oct 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SmarterStats Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of SmarterStats.

  The script sends a connection request to the server and attempts to detect SmarterStats and its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

Port = get_http_port(default: 8080);

res = http_get_cache(item: "/login.aspx", port: Port);

if("Login to SmarterStats" >< res || ">SmarterStats" >< res) {

    version = "unknown";
    set_kb_item(name:"smarterstats/installed", value:TRUE);

    ver = eregmatch(pattern:'href="http://help.smartertools.com/smarterstats/v([0-9]+)/default.aspx[?]p=U&amp;v=([0-9.]+)', string:res);

    if (!isnull(ver[2]))    version = ver[2];

    cpe = build_cpe(value:version, exp: "^([0-9.]+)",  base:"cpe:/a:smartertools:smarterstats:");
    if (!cpe)
      cpe = 'cpe:/a:smartertools:smarterstats';

    register_product(cpe: cpe, location: "/", port: Port);

    log_message( data:build_detection_report(app:"SmarterStats", version: version, install: "/", cpe:cpe), port:Port);
}

exit(0);
