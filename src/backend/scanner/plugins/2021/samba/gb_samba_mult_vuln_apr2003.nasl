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

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150715");
  script_version("2021-09-29T04:35:02+0000");
  script_tag(name:"last_modification", value:"2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-09-24 10:59:30 +0000 (Fri, 24 Sep 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2003-0196", "CVE-2003-0201");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Samba 2.0.0 <= 2.2.8 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_tag(name:"summary", value:"Samba is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2003-0196:

  A buffer overrun condition exists in the SMB/CIFS packet fragment
  re-assembly code in smbd which would allow an attacker to cause smbd
  to overwrite arbitrary areas of memory in its own process address
  space. This could allow a skilled attacker to inject binary specific
  exploit code into smbd.

  This version of Samba adds explicit overrun and overflow checks on
  fragment re-assembly of SMB/CIFS packets to ensure that only valid
  re-assembly is performed by smbd.

  In addition, the same checks have been added to the re-assembly
  functions in the client code, making it safe for use in other
  services.

  - CVE-2003-0201:

  This vulnerability, if exploited correctly, leads to an anonymous
  user gaining root access on a Samba serving system. All versions
  of Samba up to and including Samba 2.2.8 are vulnerable. An active
  exploit of the bug has been reported in the wild. Alpha versions of
  Samba 3.0 and above are *NOT* vulnerable.");

  script_tag(name:"affected", value:"Samba versions 2.0.0 through 2.2.8.");

  script_tag(name:"solution", value:"Update to version 2.2.8a or later.");

  script_xref(name:"URL", value:"https://www.samba.org/samba/history/samba-2.2.8a.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2.0.0", test_version2: "2.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.8a", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
