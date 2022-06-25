##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_extremexos_vn-2016-001-openssh.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Extreme ExtremeXOS OpenSSH Vulnerabilities
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

CPE = 'cpe:/a:extreme:extremexos';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106425");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-11-29 08:20:28 +0700 (Tue, 29 Nov 2016)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2016-0777", "CVE-2016-0778");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Extreme ExtremeXOS OpenSSH Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_extremeos_snmp_detect.nasl");
  script_mandatory_keys("extremexos/detected");

  script_tag(name:"summary", value:"Extreme ExtremeXOS is prone to multiple OpenSSH vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Roaming is enabled by default in the OpenSSH client, and contains two
vulnerabilities that can be exploited by a malicious SSH server (or a trusted but compromised server):

  - An information leak (memory disclosure). (CVE-2016-0777)

  - A buffer overflow(heap-based). (CVE-2016-0778)");

  script_tag(name:"impact", value:"An attacker may obtain sensitive information or cause a denial of service
condition.");

  script_tag(name:"affected", value:"Version 15.7 and later.");

  script_tag(name:"solution", value:"Upgrade to 15.7.3 Patch 1-8, 16.2.1, 16.1.3, 22.1.1 or later.");

  script_xref(name:"URL", value:"https://gtacknowledge.extremenetworks.com/articles/Vulnerability_Notice/VN-2016-001-OpenSSH");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_is_less(version: version, test_version: "15.7.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.7.3 Patch 1-8");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "15\.7\.3") {
  patch = get_kb_item("extremexos/patch");
  if (!patch || version_is_less(version: patch, test_version: "1.8")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.7.3 Patch 1-8");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version_is_greater(version: version, test_version: "16.1.1") &&
    version_is_less(version: version, test_version: "16.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.1.3");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_greater(version: version, test_version: "21.1.1") &&
    version_is_less(version: version, test_version: "22.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.1.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
