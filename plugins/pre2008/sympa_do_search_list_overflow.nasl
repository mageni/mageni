# OpenVAS Vulnerability Test
# Description: Sympa wwsympa do_search_list Overflow DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.14298");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Sympa wwsympa do_search_list Overflow DoS");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Update to version 4.1.2 or newer.");

  script_tag(name:"summary", value:"This version of Sympa has a flaw in one of it's scripts
  (wwsympa.pl) which would allow a remote attacker to overflow the sympa server. Specifically,
  within the cgi script wwsympa.pl is a do_search_list function which fails to perform
  bounds checking.");

  script_tag(name:"impact", value:"An attacker, passing a specially formatted long string
  to this function, would be able to crash the remote sympa server. At the
  time of this writing, the attack is only known to cause a Denial of Service
  (DoS).");

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

  if ("www.sympa.org" >< r) {
    # jwl : through 3.3.5.1 vuln
    if(egrep(pattern:"www\.sympa\.org.*ALT=.Sympa ([0-2]\.|3\.[0-2]|3\.3\.[0-4]|3\.3\.5\.[01])", string:r)) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);