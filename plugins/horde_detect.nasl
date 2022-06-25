###############################################################################
# OpenVAS Vulnerability Test
# $Id: horde_detect.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Horde Detection
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2004 George A. Theall
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.15604");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Horde Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.horde.org/");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract
  the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);
host = http_host_name(dont_add_port: TRUE);
if(http_get_no404_string(port: port, host: host)) exit(0);

# Search for Horde in a couple of different locations in addition to cgi_dirs().
dirs = make_list_unique( cgi_dirs(port:port), "/horde", "/" );

foreach dir (dirs) {
  # Search for version number in a couple of different pages.
  files = make_list(
    "/services/help/?module=horde&show=menu",
   "/services/help/?module=horde&show=about",
   "/test.php", "/lib/version.phps",
   "/status.php3"
  );

  install = dir;
  if (dir == "/")
    dir = "";

  foreach file (files) {

    req = http_get(item:string(dir, file), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if (res == NULL) continue;
    if (egrep(string:res, pattern:"^HTTP/1\.. 200 ")) {
      # Specify pattern used to identify version string.
      # - version 3.x
      if (file =~ "^/services/help") {

        if("about" >< file)
          pat = ">This is Horde (.+).</h2>";
        if("menu" >< file)
          pat = '>Horde ([0-9.]+[^<]*)<';

      }
      #   nb: test.php available is itself a vulnerability but sometimes available.
      else if (file == "/test.php") {
        pat = "^ *<li>horde: +(.+) *</li> *$";
      }
      #   nb: another security risk -- ability to view PHP source.
      else if (file == "/lib/version.phps") {
        pat = "HORDE_VERSION', '(.+)'";
      }
      # - version 1.x
      else if (file == "/status.php3") {
        pat = ">Horde, Version (.+)<";
      }
      # - someone updated files but forgot to add a pattern???
      else {
        exit(1);
      }

      version = "unknown";

      vers = eregmatch(pattern: pat, string: res);
      if (!vers) continue;
      if (!isnull(vers[1])) {
        version = vers[1];
        concUrl = file;
      }

      set_kb_item(name:"horde/installed", value:TRUE);

      cpe = build_cpe(value: version, exp:"^([0-9.]+)",base:"cpe:/a:horde:horde_groupware:");
      if (!cpe)
        cpe = 'cpe:/a:horde:horde_groupware';

      register_product(cpe: cpe, location: install, port: port);

      log_message(data: build_detection_report(app: "Horde", version: version, install: install, cpe: cpe,
                                               concluded: version, concludedUrl: concUrl),
                  port: port);
      exit(0);
    }
  }
}

exit(0);
