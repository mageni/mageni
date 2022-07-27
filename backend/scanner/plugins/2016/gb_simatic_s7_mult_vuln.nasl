##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simatic_s7_mult_vuln.nasl 11569 2018-09-24 10:29:54Z asteins $
#
# Siemens SIMATIC S7-300/400 PLC Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106476");
  script_version("$Revision: 11569 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-24 12:29:54 +0200 (Mon, 24 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-12-15 10:22:34 +0700 (Thu, 15 Dec 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2016-9158", "CVE-2016-9159");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Siemens SIMATIC S7-300/400 PLC Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_simatic_s7_version.nasl");
  script_mandatory_keys("simatic_s7/detected", "simatic_s7/version");

  script_tag(name:"summary", value:"Siemens SIMATIC S7-300 and S7-400 are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a HTTP port or the COTP port is open.");

  script_tag(name:"insight", value:"Siemens SIMATIC S7-300 and S7-400 are prone to multiple vulnerabilities:

  - Specially crafted packets sent to Port 80/TCP could cause the affected devices to go into defect mode.
(CVE-2016-9158)

  - An attacker with network access to Port 102/TCP (ISO-TSAP) could obtain credentials from the PLC if
Protection-level 2 is configured on the affected devices. (CVE-2016-9159)");

  script_tag(name:"impact", value:"A remote attacker may cause a DoS condition or obtain credentials.");

  script_tag(name:"affected", value:"S7-300 CPU firmware version prior to 3.X.14, S7-400 PN V6 firmware version
prior to 6.0.6, S7-400 V7 firmware version prior to 7.0.2 and S7-CPU 410 CPU firmware version prior to 8.2.0.");

  script_tag(name:"solution", value:"Siemens provides updated firmware versions.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-348-05");
  script_xref(name:"URL", value:"https://www.siemens.com/cert/pool/cert/siemens_security_advisory_ssa-731239.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

model = get_kb_item("simatic_s7/model");

if (model !~ "^(3|4)[0-9]{2}")
  exit(0);

moduleType = get_kb_item("simatic_s7/modtype");

if (!fw = get_kb_item("simatic_s7/version"))
  exit(0);

if (model =~ "^3") {
  if ((moduleType =~ "^CPU 314C" || model =~ "^314C") && version_is_less(version: fw, test_version: "3.3.14")) {
    report = report_fixed_ver(installed_version: fw, fixed_version: "3.3.14");
    security_message(port: 0, data: report);
    exit(0);
  }

  if ((moduleType =~ "^CPU 3(15|17|19)" || model =~ "^3(15|17|19)") &&
      version_is_less(version: fw, test_version: "3.2.14")) {
    report = report_fixed_ver(installed_version: fw, fixed_version: "3.2.14");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (moduleType =~ "^CPE 41(2|4|6).*PN/DP$" && version_is_less(version: fw, test_version: "6.0.6")) {
  report = report_fixed_ver(installed_version: fw, fixed_version: "6.0.6");
  security_message(port: 0, data: report);
  exit(0);
}

if (moduleType =~ "^CPE 41(2|4|6)$" && version_in_range(version: fw, test_version: "7", test_version2: "7.0.1")) {
  report = report_fixed_ver(installed_version: fw, fixed_version: "7.0.2");
  security_message(port: 0, data: report);
  exit(0);
}

if (moduleType =~ "^CPU 410" && version_is_less(version: fw, test_version: "8.2.0")) {
  report = report_fixed_ver(installed_version: fw, fixed_version: "8.2.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);

