###############################################################################
# OpenVAS Vulnerability Test
# $Id: axigen_web_detect.nasl 10890 2018-08-10 12:30:06Z cfischer $
#
# Axigen Web Detection
#
# Authors:
# Michael Meyer
#
# Updated By Shakeel <bshakeel@secpod.com> on 07-07-2014
# According to CR57 and new script style
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100176");
  script_version("$Revision: 10890 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:30:06 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Axigen Web Detection");

  script_tag(name:"summary", value:"Detects the installed version of Axigen.

This script sends HTTP GET request and try to get the version from the response, and sets the result in KB.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

axPort = get_http_port(default:80);

url = "/index.hsp?login=";

buf = http_get_cache(port: axPort, item: url);

if (egrep(pattern: 'Server: Axigen-.*', string: buf, icase: TRUE)) {
  app_found = eregmatch(string: buf, pattern: 'Server: Axigen-(Webmail|Webadmin)',icase:TRUE);
  if (!isnull(app_found[1]))
    axigen_app = app_found[1];

  vers = "unknown";

  version = eregmatch(string: buf, pattern: '<title>AXIGEN Web[mail|admin]+[^0-9]+([0-9.]+)</title>',icase:TRUE);

  if (!isnull(version[1]))
    vers=version[1];
  else
  {
    version = eregmatch(string: buf, pattern: ">[V|v]ersion ([0-9.]+)<");
    if (!isnull(version[1]))
      vers = version[1];
    else {
      # e.g. lib_login.js?v=1000
      version = eregmatch(string: buf, pattern: "\?v=([0-9.]+)");
      if (!isnull(version[1]) && strlen(version[1]) == 4) {
        vers = version[1];
        vers = substr(vers, 0, 1) + '.' + vers[2] + '.' + vers[3];
      }
    }
  }

  set_kb_item(name: "axigen/installed", value: TRUE);

  cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:gecad_technologies:axigen_mail_server:");
  if (isnull(cpe))
    cpe = "cpe:/a:gecad_technologies:axigen_mail_server";

  register_product(cpe: cpe, location: "/", port: axPort);

  log_message(data: build_detection_report(app:"Axigen " + axigen_app, version: vers, install: "/",
                                           cpe: cpe, concluded: version[0]),
              port: axPort);
  exit(0);
}

exit(0);
