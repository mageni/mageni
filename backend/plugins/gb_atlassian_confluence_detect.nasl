###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atlassian_confluence_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Atlassian Confluence Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# Updated to detect new version
#   - By Kashinath T <tkashinath@secpod.com> on 2016-01-11
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
  script_oid("1.3.6.1.4.1.25623.1.0.103152");
  script_version("$Revision: 11885 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-05-02 15:13:22 +0200 (Mon, 02 May 2011)");
  script_name("Atlassian Confluence Detection");

  script_tag(name:"summary", value:"Detection of Atlassian Confluence.

 The script sends a connection request to the server and attempts to
 extract the version number from the reply.");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

cfport = get_http_port(default:80);

foreach dir (make_list_unique("/", "/confluence", "/wiki", cgi_dirs(port:cfport))) {

  install = dir;
  if( dir == "/" ) dir = "";

  req = http_get(item: dir + "/login.action", port:cfport);
  buf = http_keepalive_send_recv( port:cfport, data:req, bodyonly:TRUE );

  if((egrep(pattern: "Powered by <a[^>]+>Atlassian Confluence", string: buf, icase: TRUE) &&
      egrep(pattern: '<form.*name="loginform" method="POST" action="[^"]*/dologin.action"', string: buf, icase: TRUE)) ||
                     "<title>Log In - Confluence" >< buf) {

    vers = "unknown";

    version = eregmatch(string: buf, pattern: "Powered by <a[^>]+>Atlassian Confluence</a>.*>([0-9.]+)",icase:TRUE);
    if( !isnull(version[1]) ) {
      vers=chomp(version[1]);
    } else {
      version = eregmatch(string: buf, pattern: 'class="hover-footer-link">Atlassian Confluence</a>.*>([0-9.]+)',icase:TRUE);
    }

    if ( !isnull(version[1]) ) {
      vers=chomp(version[1]);
    }

    tmp_version = vers + " under " + install;
    set_kb_item(name:"www/" + cfport + "/atlassian_confluence", value:tmp_version );
    set_kb_item(name:"atlassian_confluence/installed", value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:atlassian:confluence:");
    if(isnull(cpe))
      cpe = 'cpe:/a:atlassian:confluence';

    register_product(cpe:cpe, location:install, port:cfport);

    log_message(data: build_detection_report(app: "Atlassian Confluence",
                                             version: vers,
                                             install: install,
                                             cpe: cpe,
                                             concluded: version[0]),
                                             port: cfport);

    exit(0);

  }
}

exit(0);
