##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mikrotik_mult_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# MikroTik RouterOS Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141395");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-24 14:27:31 +0700 (Fri, 24 Aug 2018)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2018-1156", "CVE-2018-1157", "CVE-2018-1158", "CVE-2018-1159");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to multiple vulnerabilitites.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MikroTik RouterOS is prone to multiple vulnerabilitites:

  - Stack buffer overflow through the license upgrade interface (CVE-2018-1156)

  - Memory exhaustion vulnerability (CVE-2018-1157)

  - Stack exhaustion vulnerability (CVE-2018-1158)

  - Memory corruption vulnerability (CVE-2018-1159)");

  script_tag(name:"affected", value:"MikroTik RouterOS prior to version 6.42.7 and 6.40.9.");

  script_tag(name:"solution", value:"Update to version 6.43, 6.42.7, 6.40.9 or later.");

  script_xref(name:"URL", value:"https://blog.mikrotik.com/security/security-issues-discovered-by-tenable.html");
  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs/bugfix-release-tree");
  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs/release-candidate-release-tree");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.40.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.40.9");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.41", test_version2: "6.42.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.42.7");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
