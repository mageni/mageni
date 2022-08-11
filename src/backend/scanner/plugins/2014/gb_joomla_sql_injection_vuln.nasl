###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_sql_injection_vuln.nasl 2014-02-10 14:01:01Z feb$
#
# Joomla SQL Injection Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804310");
  script_version("$Revision: 11214 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-04 12:09:46 +0200 (Tue, 04 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-02-10 21:04:07 +0530 (Mon, 10 Feb 2014)");

  script_name("Joomla SQL Injection Vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"The host is running Joomla and is prone to SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
is possible to execute a sql query.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of 'id' parameter passed to
'index.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary SQL
commands in applications database and gain complete control over the vulnerable web application.");

  script_tag(name:"affected", value:"Joomla version 3.2.1 and probably other versions.");

  script_tag(name:"solution", value:"Upgrade to version 3.2.3 or later.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/31459/");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/joomla-321-sql-injection");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!jmPort = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:jmPort))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/index.php/weblinks-categories?id=/';

if (http_vuln_check(port:jmPort, url:url, pattern:"report the error below",
                   extra_check:make_list("tag_id", "SQL=SELECT"))) {
  report = report_vuln_url(port: jmPort, url: url);
  security_message(port: jmPort, data: report);
  exit(0);
}

exit(0);
