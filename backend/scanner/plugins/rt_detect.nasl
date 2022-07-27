###############################################################################
# OpenVAS Vulnerability Test
# $Id: rt_detect.nasl 10891 2018-08-10 12:51:28Z cfischer $
#
# RT: Request Tracker Detection
#
# Authors:
# Michael Meyer
#
# Updated By : Sooraj KS <kssooraj@secpod.com> on 2011-04-27
#   -Modified the regex for detecting RC versions.
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-07-24
# Updated according to CR57
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100385");
  script_version("$Revision: 10891 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:51:28 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-12-09 13:16:50 +0100 (Wed, 09 Dec 2009)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("RT: Request Tracker Detection");

  script_tag(name:"summary", value:"Detects the installed version of Request Tracker.

  This script sends HTTP GET request and try to get the version from the response.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

http_port = get_http_port(default:80);

foreach dir( make_list_unique( "/rt", "/tracker", cgi_dirs( port:http_port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + "/index.html";
  buf = http_get_cache( item:url, port:http_port );
  if( buf == NULL ) continue;

  if(egrep(pattern: "&#187;&#124;&#171; RT.*Best Practical Solutions, LLC", string: buf, icase: TRUE))
  {
    vers = string("unknown");
    version = eregmatch(string: buf, pattern: "&#187;&#124;&#171; RT ([0-9.]+)(rc[0-9]+)?",icase:TRUE);

    if( !isnull(version[1]) && !isnull(version[2])) {
      vers=chomp(version[1]) + "." + chomp(version[2]);
    }
    else if ( !isnull(version[1]) && isnull(version[2])) {
      vers=chomp(version[1]);
    }

    tmp_version = string(vers, " under ", install);
    set_kb_item(name: string("www/", http_port, "/rt_tracker"), value: tmp_version);
    set_kb_item(name:"RequestTracker/installed", value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:best_practical_solutions:request_tracker:");
    if(!cpe)
      cpe = "cpe:/a:best_practical_solutions:request_tracker";

    register_product(cpe:cpe, location:install, port: http_port);

    log_message(data: build_detection_report(app:"Request Tracker (RT)",
                                             version:vers,
                                             install:install,
                                             cpe:cpe,
                                             concluded:vers),
                                             port:http_port);
  }
}
