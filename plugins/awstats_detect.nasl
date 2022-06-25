###############################################################################
# OpenVAS Vulnerability Test
# $Id: awstats_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# AWStats Detection
#
# Authors:
# Michael Meyer
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
  script_oid("1.3.6.1.4.1.25623.1.0.100376");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2009-12-03 12:57:42 +0100 (Thu, 03 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("AWStats Detection");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running AWStats, a free powerful and featureful tool that
generates advanced web, streaming, ftp or mail server statistics, graphically.");

  script_xref(name:"URL", value:"http://awstats.sourceforge.net/");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:80);

foreach dir (make_list_unique("/awstats", "/stats", "/logs", "/awstats/cgi-bin", "/statistics", "/statistik/cgi-bin", "/awstats-cgi", cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + '/awstats.pl?framename=mainright';
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if ('content="Awstats - Advanced Web Statistics' >!< buf && "AWStats UseFramesWhenCGI" >!<buf &&
      "Created by awstats" >!< buf && "CreateDirDataIfNotExists" >!< buf ) {
    buf = http_get_cache(port: port, item: "/");
    if ('content="Awstats - Advanced Web Statistics' >!< buf && "AWStats UseFramesWhenCGI" >!<buf &&
      "Created by awstats" >!< buf && "CreateDirDataIfNotExists" >!< buf )
      continue;
  }

  if ('content="Awstats - Advanced Web Statistics' >< buf || "AWStats UseFramesWhenCGI" ><buf ||
      "Created by awstats" >< buf || "CreateDirDataIfNotExists" >< buf ) {
    vers = "unknown";

    version = eregmatch(string: buf, pattern: "Advanced Web Statistics ([0-9.]+)", icase:TRUE);
    if (!isnull(version[1]))
      vers = version[1];

    set_kb_item(name: "awstats/installed", value: TRUE);

    cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:awstats:awstats:");
    if (!cpe)
      cpe = 'cpe:/a:awstats:awstats';

    register_product(cpe: cpe, location: install, port: port);

    log_message(data: build_detection_report(app: "AWStats", version: vers, install: install, cpe: cpe,
                                             concluded: version[0]),
                port: port);
    exit(0);
  }
}

exit(0);
