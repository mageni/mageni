###############################################################################
# OpenVAS Vulnerability Test
# $Id: joomla_sql_injection_cve_2015_7297.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Joomla Core SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105419");
  script_version("$Revision: 11872 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-22 19:38:14 +0200 (Thu, 22 Oct 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-7297", "CVE-2015-7857", "CVE-2015-7858", "CVE-2015-7859",
                "CVE-2015-7899");

  script_name("Joomla Core SQL Injection Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");

  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla is prone to a SQL-Injection vulnerability.");

  script_tag(name:"vuldetect", value:"Try to inject SQL code");

  script_tag(name:"insight", value:"An SQL Injection vulnerability exists in the file
'/administrator/components/com_contenthistory/models/history.php' a core module installed as part of a default
Joomla installation.");

  script_tag(name:"impact", value:"CVE-2015-7857 enables an unauthorized remote user to gain administrator
privileges by hijacking the administrator session. Following exploitation of the vulnerability, the attacker
may gain full control of the web site and execute additional attacks.");

  script_tag(name:"affected", value:"Joomla CMS versions 3.2.0 through 3.4.4");

  script_tag(name:"solution", value:"Update to 3.4.5 or later.");

  script_xref(name:"URL", value:"https://www.joomla.org/announcements/release-news/5634-joomla-3-4-5-released.html");
  script_xref(name:"URL", value:"http://developer.joomla.org/security-centre/628-20151001-core-sql-injection.html");
  script_xref(name:"URL", value:"https://www.trustwave.com/Resources/SpiderLabs-Blog/Joomla-SQL-Injection-Vulnerability-Exploit-Results-in-Full-Administrative-Access/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

CPE = 'cpe:/a:joomla:joomla';

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + '/index.php?option=com_contenthistory&view=history&list[select]=1';

if( http_vuln_check( port:port, url:url, pattern:"Unknown column", extra_check:make_list( "Array","order clause","SQL=SELECT 1" ) ) )
{
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

