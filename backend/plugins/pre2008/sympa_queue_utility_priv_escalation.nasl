# OpenVAS Vulnerability Test
# Description: Sympa queue utility privilege escalation vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.16387");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(12527);
  script_cve_id("CVE-2005-0073");
  script_name("Sympa queue utility privilege escalation vulnerability");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Update to Sympa version 4.1.3 or newer.");

  script_tag(name:"summary", value:"The remote version of Sympa contains a vulnerability which can be
  exploited by malicious local user to gain escalated privileges.");

  script_tag(name:"impact", value:"This issue is due to a boundary error in the queue utility when
  processing command line arguments. This can cause a stack based buffer overflow.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir (make_list_unique("/", "/wws", "/wwsympa", cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  r = http_get_cache(item:string(dir, "/home"), port:port);
  if(!r)
    continue;

  if ("http://www.sympa.org/" >< r) {
    if(egrep(pattern:".*ALT=.Sympa (2\.|3\.|4\.0|4\.1\.[012][^0-9])", string:r)) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);