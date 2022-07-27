###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_arista_eos_dos_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Arista EOS DoS Vulnerability
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

CPE = "cpe:/o:arista:eos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106495");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-05 11:09:21 +0700 (Thu, 05 Jan 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2016-6894");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Arista EOS DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_arista_eos_snmp_detect.nasl");
  script_mandatory_keys("arista/eos/detected", "arista/eos/model");

  script_tag(name:"summary", value:"Arista EOS on DCS-7050 series is prone to a denial of service
vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By sending crafted packets to the control plane it is possible to cause
a denial of service condition (device reboot).");

  script_tag(name:"affected", value:"Arista EOS 4.15.2F and later.");

  script_tag(name:"solution", value:"Upgrade to EOS version 4.15.8M, 4.16.7M, 4.17.0F or later.");

  script_xref(name:"URL", value:"https://www.arista.com/en/support/advisories-notices/security-advisories/1752-security-advisory-25");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

model = get_kb_item("arista/eos/model");
if (model !~ "^DCS-7050(S|T|Q)")
  exit(0);

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_is_less(version: version, test_version: "4.15.2F"))
  exit(99);

if (version_is_less(version: version, test_version: "4.15.8M")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.15.8M");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^4\.16") {
  if (version_is_less(version: version, test_version: "4.16.7M")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.16.7M");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^4\.17\.0") {
  if (version_is_less(version: version, test_version: "4.17.0F")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.17.0F");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(0);
