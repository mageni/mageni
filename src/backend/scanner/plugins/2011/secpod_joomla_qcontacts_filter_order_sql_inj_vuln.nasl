##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_qcontacts_filter_order_sql_inj_vuln.nasl 11552 2018-09-22 13:45:08Z cfischer $
#
# Joomla! QContacts Component 'filter_order' Parameter SQL Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902594");
  script_version("$Revision: 11552 $");
  script_bugtraq_id(50981);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 15:45:08 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-12-13 12:12:12 +0530 (Tue, 13 Dec 2011)");

  script_name("Joomla! QContacts Component 'filter_order' Parameter SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71707");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18218");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/107650/joomlaqcontacts106-sql.txt");

  script_tag(name:"qod_type", value:"remote_active");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause SQL Injection attack and
gain sensitive information.");

  script_tag(name:"affected", value:"Joomla! QContacts Component version 1.0.6");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input via the
'filter_order' parameter to index.php, which allows attacker to manipulate SQL queries by injecting arbitrary SQL
code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Joomla! QContacts component and is prone to SQL
injection vulnerability.");

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

url = dir + "/index.php?option=com_qcontacts?=catid=0&filter_order=[SQLi]&filter_order_Dir=&option=com_qcontacts";

if (http_vuln_check(port: port, url: url, check_header: TRUE,
    pattern: "mysql_num_rows\(\): supplied argument is not a valid MySQL")) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
