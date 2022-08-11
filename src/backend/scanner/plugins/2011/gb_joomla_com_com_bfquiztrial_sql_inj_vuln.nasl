##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_com_com_bfquiztrial_sql_inj_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Joomla 'BF Quiz' Component 'catid' Parameter SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802535");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2010-5032");
  script_bugtraq_id(40435);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-06 13:16:11 +0530 (Tue, 06 Dec 2011)");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla 'BF Quiz' Component 'catid' Parameter SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39960");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58979");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/90080/joomlabfquiz-sql.txt");
  script_xref(name:"URL", value:"http://xenuser.org/documents/security/joomla_com_bfquiz_sqli.txt");

  script_tag(name:"qod_type", value:"remote_active");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to manipulate SQL queries by
injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"Joomla BF Quiz (com_bfquiztrial) component prior to 1.3.1");

  script_tag(name:"insight", value:"The flaw is due to an input passed via the 'catid' parameter to 'index.php'
is not properly sanitised before being used in SQL queries.");

  script_tag(name:"solution", value:"Upgrade to Joomla BF Quiz component version 1.3.1 or later.");

  script_tag(name:"summary", value:"This host is running Joomla! with BF Quiz component and is prone to SQL
injection vulnerability.");

  script_xref(name:"URL", value:"http://extensions.joomla.org/extensions/vertical-markets/education-a-culture/quiz/8142");
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

url = dir + "/index.php?option=com_bfquiztrial&view=bfquiztrial&catid=1";

if (http_vuln_check(port: port, url:url, pattern:"You have an error in your SQL syntax;")) {
 report = report_vuln_url(port: port, url: url);
 security_message(port: port, data: report);
 exit(0);
}

exit(99);
