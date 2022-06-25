###############################################################################
# OpenVAS Vulnerability Test
# $Id: savant_cgi_download.nasl 10288 2018-06-21 13:26:05Z cfischer $
#
# Savant original form CGI access
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10623");
  script_version("$Revision: 10288 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-21 15:26:05 +0200 (Thu, 21 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1313);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2000-0521");
  script_name("Savant original form CGI access");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_dependencies("gb_get_http_banner.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Savant/banner");

  script_xref(name:"URL", value:"http://www.securiteam.com/exploits/Savant_Webserver_exposes_CGI_script_source.html");

  script_tag(name:"summary", value:"A security vulnerability in the Savant web server allows attackers to download the original form of CGIs(unprocessed).
  This would allow them to see any sensitive information stored inside those CGIs.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner)exit(0);

if ("Server: Savant/">< banner) {

  foreach dir (make_list_unique("/", cgi_dirs(port:port))) {

    if(dir == "/") dir = "";

    if (is_cgi_installed_ka(port:port, item:string(dir, "/cgitest.exe"))) {

      data = http_get(item:string(dir, "/cgitest.exe"), port:port);

      soc = http_open_socket(port);
      send(socket:soc, data:data);
      res = http_recv(socket:soc);
      http_close_socket(soc);
      if ((res[0] == string("M")) && (res[1] == string("Z"))) {
        security_message(port:port);
        exit(0);
      } else {
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);
