##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simatic_s7_mult_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Siemens SIMATIC S7 PLC Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140312");
  script_version("$Revision: 11863 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-18 11:51:47 +0700 (Fri, 18 Aug 2017)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2017-2680", "CVE-2017-2681");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Siemens SIMATIC S7 PLC Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_simatic_s7_version.nasl");
  script_mandatory_keys("simatic_s7/detected", "simatic_s7/version");

  script_tag(name:"summary", value:"Siemens SIMATIC S7 devices are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks the firmware version.");

  script_tag(name:"insight", value:"Siemens SIMATIC devices are prone to multiple vulnerabilities:

  - Specially crafted PROFINET DCP broadcast packets could cause a denial-of-service condition of affected products
on a local Ethernet segment (Layer 2). Human interaction is required to recover the systems. PROFIBUS interfaces
are not affected. (CVE-2017-2680)

  - Specially crafted PROFINET DCP packets sent on a local Ethernet segment (Layer 2) to an affected product could
cause a denial-of-service condition in that product. Human interaction is required to recover the system. PROFIBUS
interfaces are not affected. (CVE-2017-2681)");

  script_tag(name:"impact", value:"A remote attacker may cause a DoS condition.");

  script_tag(name:"solution", value:"Siemens provides updated firmware versions.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-129-02");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

model = get_kb_item("simatic_s7/model");

if (model !~ "^(12|15|3|4)[0-9]{2}")
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

if (model =~ "^4") {
  if (moduleType =~ "^CPU 41(2|4|6|7)" && version_is_less(version: fw, test_version: "6.0.1")) {
    report = report_fixed_ver(installed_version: fw, fixed_version: "6.0.1");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (moduleType =~ "^CPU 410" && version_is_less(version: fw, test_version: "8.2.0")) {
    report = report_fixed_ver(installed_version: fw, fixed_version: "8.2.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if ((model == "1200" || moduleType =~ "^CPU.1200") && version_is_less(version: fw, test_version: "4.2")) {
  report = report_fixed_ver(installed_version: fw, fixed_version: "4.2");
  security_message(port: 0, data: report);
  exit(0);
}

if ((model == "1500" || moduleType =~ "^CPU.1500") && version_is_less(version: fw, test_version: "2.1.0")) {
  report = report_fixed_ver(installed_version: fw, fixed_version: "2.1.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);

