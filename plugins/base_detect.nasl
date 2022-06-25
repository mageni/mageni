###############################################################################
# OpenVAS Vulnerability Test
# $Id: base_detect.nasl 11028 2018-08-17 09:26:08Z cfischer $
#
# Basic Analysis and Security Engine Detection
#
# Authors:
# Michael Meyer
#
# Updated By Sooraj KS <kssooraj@secpod.com>
# date update: 2010/05/14
# Modified url from '/index.php' to '/base_main.php
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100322");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11028 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 11:26:08 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-10-29 12:31:54 +0100 (Thu, 29 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Basic Analysis and Security Engine Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running Basic Analysis and Security Engine (BASE). BASE provides
  a web front-end to query and analyze the alerts coming from a SNORT IDS system.");

  script_xref(name:"URL", value:"https://sourceforge.net/projects/secureideas/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/base", "/snort/base", cgi_dirs( port:port ) ) ) {
  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/";
  buf = http_get_cache(port: port, item: url);

  if(egrep(pattern: "<title>Basic Analysis and Security Engine \(BASE\)", string: buf, icase: TRUE) ) {
    vers = "unknown";

    version = eregmatch(string: buf, pattern: "BASE[)</a>]* ([0-9.]+)",icase:TRUE);

    if (!isnull(version[1]))
      vers=chomp(version[1]);

    tmp_version = string(vers," under ",install);
    set_kb_item(name: string("www/", port, "/BASE"), value: tmp_version);
    set_kb_item(name:"BASE/installed",value:TRUE);

    cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:secureideas:base:");
    if (!cpe)
      cpe = 'cpe:/a:secureideas:base';

    register_product(cpe: cpe, location: install, port: port);

    log_message(data: build_detection_report(app: "Basic Analysis and Security Engine (BASE)", version: vers,
                                             install: install, cpe: cpe, concluded: version[0]),
                port: port);
    exit(0);
  }
}

exit(0);
