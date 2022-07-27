# OpenVAS Vulnerability Test
# $Id: upb_info_leak.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Ultimate PHP Board Information Leak
#
# Authors:
# Erik Stephens <erik@edgeos.com>
#
# Copyright:
# Copyright (C) 2004 Edgeos, Inc.
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12198");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-2276");
  script_bugtraq_id(6333);
  script_name("Ultimate PHP Board Information Leak");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Edgeos, Inc.");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the latest version.");

  script_tag(name:"summary", value:"The remote host is running Ultimate PHP Board (UPB).

  There is a flaw in this version which may allow an attacker to view
  private message board information.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))
  exit(0);

foreach dir( make_list_unique( "/upb", "/board", cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = string(dir, "/db/users.dat");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if(!res)
    continue;

  if(egrep(pattern:"^Admin<~>", string:res)) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );