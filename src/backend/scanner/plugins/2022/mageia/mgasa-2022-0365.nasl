# Copyright (C) 2022 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0365");
  script_cve_id("CVE-2022-42010", "CVE-2022-42011", "CVE-2022-42012");
  script_tag(name:"creation_date", value:"2022-10-10 04:44:17 +0000 (Mon, 10 Oct 2022)");
  script_version("2022-10-13T04:43:57+0000");
  script_tag(name:"last_modification", value:"2022-10-13 04:43:57 +0000 (Thu, 13 Oct 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-11 18:51:00 +0000 (Tue, 11 Oct 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0365)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0365");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0365.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30941");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/10/06/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dbus' package(s) announced via the MGASA-2022-0365 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A syntactically invalid type signature with incorrectly nested parentheses
and curly brackets would cause an assertion failure in debug builds.
Similar messages could potentially result in a crash or incorrect message
processing in a production build, although we are not aware of a practical
example. (CVE-2022-42010)

An invalid array of fixed-length elements where the length of the array is
not a multiple of the length of the element would cause an assertion
failure in debug builds or an out-of-bounds read in production builds.
(CVE-2022-42011)

A message in non-native endianness with out-of-band Unix file descriptors
would cause a use-after-free and possible memory corruption in production
builds, or an assertion failure in debug builds. (CVE-2022-42012)");

  script_tag(name:"affected", value:"'dbus' package(s) on Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"dbus", rpm:"dbus~1.13.18~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-doc", rpm:"dbus-doc~1.13.18~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-x11", rpm:"dbus-x11~1.13.18~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbus-devel", rpm:"lib64dbus-devel~1.13.18~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbus1_3", rpm:"lib64dbus1_3~1.13.18~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbus-devel", rpm:"libdbus-devel~1.13.18~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbus1_3", rpm:"libdbus1_3~1.13.18~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
