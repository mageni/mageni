# OpenVAS Vulnerability Test
# Description: CjOverkill trade.php XSS
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
  script_oid("1.3.6.1.4.1.25623.1.0.15462");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2193");
  script_bugtraq_id(11359);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("CjOverkill trade.php XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to version 4.0.4 or newer.");

  script_tag(name:"summary", value:"The remote server runs a version of CjOverkill, a free traffic trading
  script which is as old as or older than version 4.0.3.

  The remote version of this software is affected by a cross-site scripting vulnerability in the script
  'trade.php'. This issue is due to a failure of the application to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"As a result of this vulnerability, it is possible for a remote attacker
  to create a malicious link containing script code that will be executed in the browser of an unsuspecting
  user when followed.

  This may facilitate the theft of cookie-based authentication credentials as well as other attacks.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))
  exit(0);

url = "/trade.php";
r = http_get_cache(item:url, port:port);
if(!r)
  exit(0);

if(egrep(pattern:"<title>CjOverkill Version ([0-3]\.|4\.0\.[0-3][^0-9])</title>", string:r)) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);