# OpenVAS Vulnerability Test
# Description: PHP3 Physical Path Disclosure Vulnerability
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# www.westpoint.ltd.uk
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Ian Koenig <ian@carmichaelsecurity.com>
# Added link to the Bugtraq message archive
#
# Copyright:
# Copyright (C) 2001 Matt Moore
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
  script_oid("1.3.6.1.4.1.25623.1.0.10670");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("PHP3 Physical Path Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://online.securityfocus.com/archive/1/65078");
  script_xref(name:"URL", value:"http://online.securityfocus.com/archive/101/184240");

  script_tag(name:"solution", value:"In the PHP configuration file change display_errors to 'Off':

  display_errors = Off");

  script_tag(name:"summary", value:"PHP3 will reveal the physical path of the webroot when asked for
  a non-existent PHP3 file if it is incorrectly configured.");

  script_tag(name:"insight", value:"Although printing errors to the output is useful for debugging
  applications, this feature should not be enabled on production servers.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))
  exit(0);

url = "/nosuchfile-10303-10310.php3";
req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req);
if(!res)
  exit(0);

if("Unable to open" >< res) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);