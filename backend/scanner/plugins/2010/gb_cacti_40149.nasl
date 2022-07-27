###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cacti_40149.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Cacti 'rra_id' Parameter SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:cacti:cacti";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100639");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-05-14 12:04:31 +0200 (Fri, 14 May 2010)");
  script_cve_id("CVE-2010-2092");
  script_bugtraq_id(40149);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Cacti 'rra_id' Parameter SQL Injection Vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40149");
  script_xref(name:"URL", value:"http://cacti.net/");
  script_xref(name:"URL", value:"http://www.php-security.org/2010/05/13/mops-2010-023-cacti-graph-viewer-sql-injection-vulnerability/index.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("cacti_detect.nasl");
  script_mandatory_keys("cacti/installed");

  script_tag(name:"summary", value:"Cacti is prone to an SQL-injection vulnerability because it fails to
sufficiently sanitize user-supplied data before using it in an SQL query.

Exploiting this issue could allow an attacker to compromise the application, access or modify data, or exploit
latent vulnerabilities in the underlying database.

Cacti versions 0.8.7e and prior are vulnerable.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: vers, test_version: "0.8.7e")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "0.8.7e");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
