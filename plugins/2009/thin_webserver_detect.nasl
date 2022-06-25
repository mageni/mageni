###############################################################################
# OpenVAS Vulnerability Test
#
# Thin Webserver Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.100300");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2009-10-11 19:51:15 +0200 (Sun, 11 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Thin Webserver Detection");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 3000);
  script_mandatory_keys("thin/banner");

  script_tag(name:"summary", value:"This host is running Thin, a Ruby web server.");

  script_xref(name:"URL", value:"http://code.macournoyer.com/thin/");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:3000);
banner = get_http_banner(port:port);
if(!banner || "Server: thin" >!< banner)exit(0);

vers = string("unknown");
version = eregmatch(string: banner, pattern: "Server: thin ([0-9.]+)",icase:TRUE);
if ( !isnull(version[1]) ) {
  vers = chomp(version[1]);
}

set_kb_item(name: string("www/", port, "/thin"), value: string(vers));

info = string("Thin Version '");
info += string(vers);
info += string("' was detected on the remote host\n");
log_message(port:port,data:info);

exit(0);