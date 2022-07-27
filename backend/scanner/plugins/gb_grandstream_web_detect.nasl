###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_grandstream_web_detect.nasl 11328 2018-09-11 12:32:47Z tpassfeld $
#
# Grandstream Web UI Detection
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.114018");
  script_version("$Revision: 11328 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-11 14:32:47 +0200 (Tue, 11 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-08-08 12:42:30 +0200 (Wed, 08 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Grandstream Web UI Detection");

  script_tag(name:"summary", value:"Detection of Grandstream Web UI.

  The script sends a connection request to the server and attempts to detect the Grandstream Web UI.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.grandstream.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/");

if("<b>Grandstream Device Configuration</b>" >< res || '<font size="1">All Rights Reserved Grandstream Networks, Inc. 2006-2008</font>' >< res) {
   #Version can only be extracted after a successful login
   version = "unknown";
   install = "/";

   conclUrl = report_vuln_url(port: port, url: "/", url_only: TRUE);

   set_kb_item(name: "grandstream/webui/detected", value: TRUE);
   set_kb_item(name: "grandstream/webui/" + port + "/detected", value: TRUE);

   register_and_report_cpe(app: "Grandstream Web UI", ver: version, base: "cpe:/a:grandstream:web_ui:", expr: "^([0-9.]+)", insloc: install, regPort: port, conclUrl: conclUrl, extra: "Login required for version detection.");
}

exit(0);
