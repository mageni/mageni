###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nedi_mult_vuln.nasl 13455 2019-02-05 07:38:02Z mmartin $
#
# NeDi < 1.7.090 Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
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

CPE = 'cpe:/a:nedi:nedi';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141894");
  script_version("$Revision: 13455 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 08:38:02 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-18 12:41:41 +0700 (Fri, 18 Jan 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-20727", "CVE-2018-20728", "CVE-2018-20729", "CVE-2018-20730", "CVE-2018-20731");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NeDi < 1.7.090 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nedi_detect.nasl");
  script_mandatory_keys("nedi/detected");

  script_tag(name:"summary", value:"NeDi is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"NeDi is prone to multiple vulnerabilities:

  - Multiple command injection vulnerabilities (CVE-2018-20727O)

  - Cross-site Request Forgery (CSRF) vulnerability (CVE-2018-20728)

  - Reflected cross-site scripting (XSS) vulnerability (CVE-2018-20729)

  - SQL injection vulnerability (CVE-2018-20730)

  - Stored cross site scripting (XSS) vulnerability (CVE-2018-20731)");

  script_tag(name:"affected", value:"NeDi prior to version 1.7Cp3.");

  script_tag(name:"solution", value:"Update to version 1.7Cp3 or later.");

  script_xref(name:"URL", value:"https://www.nedi.ch/end-of-year-update/");
  script_xref(name:"URL", value:"https://www.sakerhetskontoret.com/disclosures/nedi/report.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.7.090")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.7.090");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
