##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_honeywell_xlweb_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Honeywell XL Web Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = 'cpe:/o:honeywell:excel_web_xl';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106561");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-03 09:38:09 +0700 (Fri, 03 Feb 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-5139", "CVE-2017-5140", "CVE-2017-5141", "CVE-2017-5142", "CVE-2017-5143");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Honeywell XL Web Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_honeywell_xlweb_bacnet_detect.nasl");
  script_mandatory_keys("honeywell_xlweb/installed");

  script_tag(name:"summary", value:"Honeywell XL Web is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Honeywell XL Web is prone to multiple vulnerabilities:

  - Any user is able to disclose a password by accessing a specific URL. (CVE-2017-5139)

  - Password is stored in clear text (CVE-2017-5140)

  - An attacker can establish a new user session, without invalidating any existing session identifier, which gives
the opportunity to steal authenticated sessions. (CVE-2017-5141)

  - A user with low privileges is able to open and change the parameters by accessing a specific URL.
(CVE-2017-5142)

  - A user without authenticating can make a directory traversal attack by accessing a specific URL.
(CVE-2017-5143)");

  script_tag(name:"impact", value:"An unauthenticated attacker may obtain a password and take complete control
over the device.");

  script_tag(name:"affected", value:"XL1000C500 XLWebExe-2-01-00 and prior and XLWeb 500 XLWebExe-1-02-08 and
prior.");

  script_tag(name:"solution", value:"Users are encouraged to contact the local Honeywell HBS branch to have
their sites updated to the latest version.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-033-01");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.02.08")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Contact vendor.");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.00.00", test_version2: "2.01.00")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Contact vendor.");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
