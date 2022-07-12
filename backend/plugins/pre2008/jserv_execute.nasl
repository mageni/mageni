# OpenVAS Vulnerability Test
# Description: Oracle Jserv Executes outside of doc_root
#
# Authors:
# Michael Scheidell <scheidell at secnap.net>
# based on a script written by Hendrik Scholz <hendrik@scholz.net>
#
# Copyright:
# Copyright (C) 2002 Michael Scheidell
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
  script_oid("1.3.6.1.4.1.25623.1.0.10925");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0307");
  script_name("Oracle Jserv Executes outside of doc_root");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Michael Scheidell");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/apache");

  script_tag(name:"solution", value:"Upgrade to OJSP Release 1.1.2.0.0, available on Oracle
  Technology Network's OJSP web site.");

  script_tag(name:"summary", value:"Detects Vulnerability in the execution of JSPs outside
  doc_root.");

  script_tag(name:"insight", value:"A potential security vulnerability has been discovered in
  Oracle JSP releases 1.0.x through 1.1.1 (in Apache/Jserv). This vulnerability permits access
  to and execution of unintended JSP files outside the doc_root in Apache/Jserv. For example,
  accessing:

  http://www.example.com/a.jsp//..//..//..//..//..//../b.jsp

  will execute b.jsp outside the doc_root instead of a.jsp if there is a b.jsp file in the
  matching directory.

  Further, Jserv Releases 1.0.x - 1.0.2 have additional vulnerability:

  Due to a bug in Apache/Jserv path translation, any URL that looks like:

  http://example.com:port/servlets/a.jsp,

  makes Oracle JSP execute 'd:\servlets\a.jsp' if such a directory path actually exists. Thus,
  a URL virtual path, an actual directory path and the Oracle JSP name (when using Oracle Apache/JServ)
  must match for this potential vulnerability to occur.");

  script_tag(name:"affected", value:"Oracle8i Release 8.1.7, iAS Release version 1.0.2

  Oracle JSP, Apache/JServ Releases version 1.0.x - 1.1.1");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
str = get_http_banner(port:port);

if(ereg(pattern:".*apachejserv/1\.(0|1\.[0-1][^0-9])", string:str)) {
  security_message(port:port);
  exit(0);
}

exit(99);