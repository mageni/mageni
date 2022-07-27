###############################################################################
# OpenVAS Vulnerability Test
#
# Syncrify Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100819");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-14T08:13:05+0000");
  script_tag(name:"last_modification", value:"2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-09-22 16:24:51 +0200 (Wed, 22 Sep 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Syncrify Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 5800);
  script_mandatory_keys("Apache-Coyote/banner");

  script_tag(name:"summary", value:"This host is running Syncrify, an incremental, and cloud-ready backup
that implements the rsync protocol over HTTP.");
  script_xref(name:"URL", value:"http://web.synametrics.com/Syncrify.htm");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:5800);

banner = get_http_banner(port:port);
if(!banner || "Server: Apache-Coyote" >!< banner)exit(0);

url = string("/app?operation=about");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if(!buf)
  exit(0);

if("Syncrify" >< buf && "Synametrics Technologies" && "Fast incremental backup" >< buf)
{
  install = "/";

  vers = string("unknown");
  version = eregmatch(string: buf, pattern: "Version: ([0-9.]+) - build ([0-9]+)",icase:TRUE);

  if ( !isnull(version[1]) ) {
    vers=chomp(version[1]);
    if(!isnull(version[2])) {
      vers = vers + "." + version[2]; # ver string: Version: 2.1 build 420 -> version in kb 2.1.420
    }
  }

  set_kb_item(name: string("www/", port, "/syncrify"), value: string(vers," under ",install));
  set_kb_item(name: "syncrify/app/detected", value: TRUE); #nb: There is a "server" Detection-VT as well.

  info = string("Syncrify Version '");
  info += string(vers);
  info += string("' was detected on the remote host in the following directory(s):\n\n");
  info += string(install, "\n");

  log_message(port:port,data:info);
  exit(0);
}

exit(0);

