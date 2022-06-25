###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_mult_sql_inj_vuln.nasl 11552 2018-09-22 13:45:08Z cfischer $
#
# Joomla! Multiple SQL Injection Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801829");
  script_version("$Revision: 11552 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 15:45:08 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-01-27 07:47:27 +0100 (Thu, 27 Jan 2011)");
  script_cve_id("CVE-2010-4166", "CVE-2010-4696");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! Multiple SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42133");
  script_xref(name:"URL", value:"http://yehg.net/lab/pr0js/advisories/joomla/core/1.5.21/sql_injection/sqli_(filter_order_Dir)_front.jpg");
  script_xref(name:"URL", value:"http://yehg.net/lab/pr0js/advisories/joomla/core/1.5.21/sql_injection/sqli_(filter_order_Dir)_front.jpg");
  script_xref(name:"URL", value:"http://yehg.net/lab/pr0js/advisories/joomla/core/1.5.21/sql_injection/sqli_(filter_order_Dir)_front.jpg");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause SQL Injection attack and
gain sensitive information.");

  script_tag(name:"affected", value:"Joomla! versions 1.5.x before 1.5.22");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input via the
'filter_order' and 'filter_order_Dir' parameters to 'index.php', which allows attacker to manipulate SQL queries
by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"Upgrade to Joomla! 1.5.22 or later.");

  script_tag(name:"summary", value:"The host is running Joomla! and is prone to multiple SQL injection
vulnerabilities.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php?option=com_weblinks&view=category&id=2:joomla" +
             "-specific-links&limit=10&filter_order_Dir=&filter_order=%00";

if (http_vuln_check(port:port, url:url,
                    pattern:'mysql_num_rows(): supplied argument is not a valid MySQL result resource',
                    check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
