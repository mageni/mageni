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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0341");
  script_cve_id("CVE-2021-20197", "CVE-2021-3487");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-04 12:55:00 +0000 (Tue, 04 May 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0341)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0341");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0341.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28305");
  script_xref(name:"URL", value:"https://sourceware.org/pipermail/binutils/2021-January/115071.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils' package(s) announced via the MGASA-2021-0341 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides binutils 2.36.1 and fixes at least the following security
issues:

There's a flaw in the BFD library of binutils in versions before 2.36. An
attacker who supplies a crafted file to an application linked with BFD, and
using the DWARF functionality, could cause an impact to system availability
by way of excessive memory consumption (CVE-2021-3487).

There is an open race window when writing output in the following utilities
in GNU binutils version 2.35 and earlier:ar, objcopy, strip, ranlib. When
these utilities are run as a privileged user (presumably as part of a script
updating binaries across different users), an unprivileged user can trick
these utilities into getting ownership of arbitrary files through a symlink
(CVE-2021-20197).

For more info about the 2.36 update, see the sourceware link.");

  script_tag(name:"affected", value:"'binutils' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.36.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64binutils-devel", rpm:"lib64binutils-devel~2.36.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbinutils-devel", rpm:"libbinutils-devel~2.36.1~1.1.mga8", rls:"MAGEIA8"))) {
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
