###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_interspire_iem_detect.nasl 8142 2017-12-15 13:00:23Z cfischer $
#
# Interspire IEM Detection
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112086");
  script_version("$Revision: 8142 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 14:00:23 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-10-18 15:11:22 +0200 (Wed, 18 Oct 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Interspire IEM Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This scripts tries to detect the Interspire Email Marketer and its version on the host system.");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:80);

foreach dir (make_list_unique("/", "/iem", "/IEM", cgi_dirs(port:port)))
{
  install = dir;
  if (dir == "/") dir = "";

  url = dir + "/admin/index.php";

  res = http_get_cache(port:port, item:url);

  if (res =~ "HTTP/1\.[01] 200 OK" &&
      '<title>Control Panel</title>' >< res && '<script src="includes/js/tiny_mce/tiny_mce.js"></script>' >< res &&
      'Cookie: IEMSESSIONID' >< res &&
      ('<option value="index.php?Page=Stats">My Campaign Statistics</option>' >< res ||
       'var UnsubLinkPlaceholder = "Unsubscribe me from this list";' >< res ||
       "$(document.frmLogin.ss_takemeto).val('index.php');" >< res ||
       '<td style="padding:10px 0px 5px 0px">Login with your username and password below.</td>' >< res ))
  {
    set_kb_item(name:"interspire/iem/installed", value:TRUE);
    version = "unknown";

    if (ver = eregmatch(pattern:"Powered by.* ([0-9.]+)</a>", string:res, icase:TRUE))
    {
      version = ver[1];
      concUrl = report_vuln_url(port:port, url:url, url_only:TRUE);

      set_kb_item(name:"interspire/iem/version", value:version);
      set_kb_item(name:"www/" + port + "/iem", value:version + " under " + install);
    }

    if (!cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:interspire:iem:"))
      cpe = "cpe:/a:interspire:iem";

    register_product(cpe:cpe, location:install, port:port);

    log_message(data:build_detection_report(app:"Interspire Email Marketer",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:ver[0],
                                            concludedUrl:concUrl),
                port:port);
    exit(0);
  }
}

exit(0);
