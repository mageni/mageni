###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dolibarr_mult_vuln.nasl 12936 2019-01-04 04:46:08Z ckuersteiner $
#
# Dolibarr < 6.0.5 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:dolibarr:dolibarr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112216");
  script_version("$Revision: 12936 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-04 05:46:08 +0100 (Fri, 04 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-02-12 10:00:40 +0100 (Mon, 12 Feb 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-17900", "CVE-2017-17898", "CVE-2017-17899", "CVE-2017-17897");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dolibarr < 6.0.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_detect.nasl");
  script_mandatory_keys("dolibarr/detected");

  script_tag(name:"summary", value:"Dolibarr ERP/CRM is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - SQL injection vulnerability in fourn/index.php allows remote attackers to execute arbitrary SQL commands via the socid parameter. (CVE-2017-17900)

  - Dolibarr does not block direct requests to *.tpl.php files, which allows remote attackers to obtain sensitive information. (CVE-2017-17898)

  - SQL injection vulnerability in adherents/subscription/info.php allows remote attackers to execute arbitrary SQL commands via the rowid parameter. (CVE-2017-17899)

  - SQL injection vulnerability in comm/multiprix.php in Dolibarr ERP/CRM version 6.0.4 allows remote attackers to execute arbitrary SQL commands via the id parameter. (CVE-2017-17897)");

  script_tag(name:"affected", value:"Dolibarr ERP/CRM version 6.0.4 and prior.");

  script_tag(name:"solution", value:"Upgrade to Dolibarr version 6.0.5.");

  script_xref(name:"URL", value:"https://github.com/Dolibarr/dolibarr/blob/develop/ChangeLog");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.5");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
