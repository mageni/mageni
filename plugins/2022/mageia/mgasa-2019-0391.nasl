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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0391");
  script_cve_id("CVE-2019-1348", "CVE-2019-1350", "CVE-2019-1387");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-28 01:15:00 +0000 (Tue, 28 Jan 2020)");

  script_name("Mageia: Security Advisory (MGASA-2019-0391)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0391");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0391.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25348");
  script_xref(name:"URL", value:"https://github.com/libgit2/libgit2/releases/tag/v0.28.3");
  script_xref(name:"URL", value:"https://github.com/libgit2/libgit2/releases/tag/v0.28.4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgit2' package(s) announced via the MGASA-2019-0391 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libgit2 has been updated to version 0.28.4 to fix several security issues:

* A carefully constructed commit object with a very large number
 of parents may lead to potential out-of-bounds writes or
 potential denial of service.

* CVE-2019-1348: the fast-import stream command 'feature
 export-marks=path' allows writing to arbitrary file paths. As
 libgit2 does not offer any interface for fast-import, it is not
 susceptible to this vulnerability.

* CVE-2019-1350: recursive clones may lead to arbitrary remote
 code executing due to improper quoting of command line
 arguments. As libgit2 uses libssh2, which does not require us
 to perform command line parsing, it is not susceptible to this
 vulnerability.

* CVE-2019-1387: it is possible to let a submodule's git
 directory point into a sibling's submodule directory, which may
 result in overwriting parts of the Git repository and thus lead
 to arbitrary command execution. As libgit2 doesn't provide any
 way to do submodule clones natively, it is not susceptible to
 this vulnerability. Users of libgit2 that have implemented
 recursive submodule clones manually are encouraged to review
 their implementation for this vulnerability.");

  script_tag(name:"affected", value:"'libgit2' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64git2-devel", rpm:"lib64git2-devel~0.28.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64git2_28", rpm:"lib64git2_28~0.28.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2", rpm:"libgit2~0.28.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2-devel", rpm:"libgit2-devel~0.28.4~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2_28", rpm:"libgit2_28~0.28.4~1.mga7", rls:"MAGEIA7"))) {
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
