###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dolibarr_mult_vuln01.nasl 12936 2019-01-04 04:46:08Z ckuersteiner $
#
# Dolibarr < 8.0.4 Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.141823");
  script_version("$Revision: 12936 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-04 05:46:08 +0100 (Fri, 04 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-04 11:04:34 +0700 (Fri, 04 Jan 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2018-19992", "CVE-2018-19993", "CVE-2018-19994", "CVE-2018-19995", "CVE-2018-19998");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dolibarr < 8.0.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_detect.nasl");
  script_mandatory_keys("dolibarr/detected");

  script_tag(name:"summary", value:"Dolibarr is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Dolibarr is prone to multiple vulnerabilities:

  - A stored cross-site scripting (XSS) vulnerability allows remote authenticated users to inject arbitrary web
script or HTML via the 'address' (POST) or 'town' (POST) parameter to adherents/type.php (CVE-2018-19992)

  - A reflected cross-site scripting (XSS) vulnerability allows remote attackers to inject arbitrary web script or
HTML via the transphrase parameter to public/notice.php (CVE-2018-19993)

  - An error-based SQL injection vulnerability in product/card.php allows remote authenticated users to execute
arbitrary SQL commands via the desiredstock parameter (CVE-2018-19994)

  - A stored cross-site scripting (XSS) vulnerability allows remote authenticated users to inject arbitrary web
script or HTML via the 'address' (POST) or 'town' (POST) parameter to user/card.php (CVE-2018-19995)

  - SQL injection vulnerability in user/card.php allows remote authenticated users to execute arbitrary SQL
commands via the employee parameter (CVE-2018-19998)");

  script_tag(name:"affected", value:"Dolibarr prior to version 8.0.4.");

  script_tag(name:"solution", value:"Update to version 8.0.4 or later.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "8.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
