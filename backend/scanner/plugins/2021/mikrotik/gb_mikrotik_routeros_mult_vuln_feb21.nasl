# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146340");
  script_version("2021-07-21T06:43:57+0000");
  script_tag(name:"last_modification", value:"2021-07-21 10:16:50 +0000 (Wed, 21 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-21 06:12:03 +0000 (Wed, 21 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2020-20213", "CVE-2020-20215", "CVE-2020-20216", "CVE-2020-20217",
                "CVE-2020-20225", "CVE-2020-20230", "CVE-2020-20248", "CVE-2020-20249",
                "CVE-2020-20250", "CVE-2020-20252", "CVE-2020-20267");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS < 6.47 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-20213: Stack exhaustion in the /nova/bin/net process

  - CVE-2020-20215: Memory corruption in the /nova/bin/diskd process

  - CVE-2020-20216: Memory corruption in the /nova/bin/graphing process

  - CVE-2020-20217: Uncontrolled resource consumption in the /nova/bin/route process

  - CVE-2020-20225: Assertion failure in the /nova/bin/user process

  - CVE-2020-20230: Uncontrolled resource consumption in the sshd process

  - CVE-2020-20248: Uncontrolled resource consumption in the memtest process

  - CVE-2020-20249: Memory corruption in the resolver process

  - CVE-2020-20250: Memory corruption in the /nova/bin/lcdstat process

  - CVE-2020-20252: Memory corruption in the /nova/bin/lcdstat process

  - CVE-2020-20267: Memory corruption in the /nova/bin/resolver process");

  script_tag(name:"affected", value:"MikroTik RouterOS prior to version 6.47.");

  script_tag(name:"solution", value:"Update to version 6.47 (long-term version) or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2021/May/10");
  script_xref(name:"URL", value:"https://github.com/cq674350529/pocs_slides/blob/master/advisory/MikroTik/CVE-2020-20217/README.md");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2021/May/12");
  script_xref(name:"URL", value:"https://github.com/cq674350529/pocs_slides/blob/master/advisory/MikroTik/CVE-2020-20230/README.md");
  script_xref(name:"URL", value:"https://github.com/cq674350529/pocs_slides/blob/master/advisory/MikroTik/CVE-2020-20248/README.md");
  script_xref(name:"URL", value:"https://github.com/cq674350529/pocs_slides/blob/master/advisory/MikroTik/CVE-2020-20249/README.md");
  script_xref(name:"URL", value:"https://github.com/cq674350529/pocs_slides/blob/master/advisory/MikroTik/CVE-2020-20250/README.md");
  script_xref(name:"URL", value:"https://github.com/cq674350529/pocs_slides/blob/master/advisory/MikroTik/CVE-2020-20252/README.md");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.47")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.47");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
