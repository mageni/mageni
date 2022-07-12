##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_com_xshop_sql_inj_vuln.nasl 11549 2018-09-22 12:11:10Z cfischer $
#
# Joomla com_x-shop 'idd' Parameter SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802706");
  script_version("$Revision: 11549 $");
  script_bugtraq_id(52077);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 14:11:10 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-03-12 19:12:57 +0530 (Mon, 12 Mar 2012)");

  script_name("Joomla com_x-shop 'idd' Parameter SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.1337day.com/exploits/17540");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73332");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52077/info");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/109938/Joomla-X-Shop-SQL-Injection.html");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to manipulate SQL queries by
injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"Joomla x-shop component");

  script_tag(name:"insight", value:"The flaw is due to an input passed via the 'idd' parameter to 'index.php'
(when 'option' is set to 'com_x-shop' & 'action' is set to 'artdetail') is not properly sanitised before being
used in a SQL query.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Joomla x-shop component and is prone to SQL injection
vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

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

url = dir + "/index.php?option=com_x-shop&action=artdetail&idd='";

if (http_vuln_check(port: port, url: url, check_header:TRUE,
                    pattern: ">:  mysql_fetch_row\(\): supplied argument is not a valid MySQL result")) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
