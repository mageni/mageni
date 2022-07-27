###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantis_49235.nasl 12958 2019-01-07 10:57:12Z cfischer $
#
# MantisBT Cross Site Scripting and SQL Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:mantisbt:mantisbt";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103214");
  script_version("$Revision: 12958 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-07 11:57:12 +0100 (Mon, 07 Jan 2019) $");
  script_tag(name:"creation_date", value:"2011-08-19 14:58:19 +0200 (Fri, 19 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2011-2938");
  script_bugtraq_id(49235);

  script_name("MantisBT Cross Site Scripting and SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49235");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/104149/mantisbt-sqlxss.txt");
  script_xref(name:"URL", value:"http://www.mantisbt.org");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("mantis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mantisbt/detected");

  script_tag(name:"summary", value:"MantisBT is prone to an SQL-injection vulnerability and a cross-site
  scripting vulnerability.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to steal cookie-
  based authentication credentials, compromise the application, access or modify data, or exploit
  latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"MantisBT 1.2.6 is vulnerable, other versions may also be affected.");

  script_tag(name:"solution", value:"Upgrade to the latest version.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_is_equal(version: version, test_version: "1.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.7", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);