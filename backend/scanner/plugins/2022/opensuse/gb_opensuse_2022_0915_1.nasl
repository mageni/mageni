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
  script_oid("1.3.6.1.4.1.25623.1.0.854575");
  script_version("2022-03-24T14:03:56+0000");
  script_cve_id("CVE-2021-4048");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-03-25 11:41:51 +0000 (Fri, 25 Mar 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-13 18:45:00 +0000 (Mon, 13 Dec 2021)");
  script_tag(name:"creation_date", value:"2022-03-23 08:29:43 +0000 (Wed, 23 Mar 2022)");
  script_name("openSUSE: Security Advisory for lapack (openSUSE-SU-2022:0915-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:0915-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6Y4WJU3KSP5LSKZL7KZ3ZTSCG3EWFTGE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lapack'
  package(s) announced via the openSUSE-SU-2022:0915-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for lapack fixes the following issues:
  - CVE-2021-4048: Fixed an out of bounds read when user input was not
       validated properly (bsc#1193562).");

  script_tag(name:"affected", value:"'lapack' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"blas-devel", rpm:"blas-devel~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"blas-devel-static", rpm:"blas-devel-static~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lapack-debugsource", rpm:"lapack-debugsource~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lapack-devel", rpm:"lapack-devel~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lapack-devel-static", rpm:"lapack-devel-static~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lapacke-devel", rpm:"lapacke-devel~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lapacke-devel-static", rpm:"lapacke-devel-static~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblas3", rpm:"libblas3~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblas3-debuginfo", rpm:"libblas3-debuginfo~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblapack3", rpm:"liblapack3~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblapack3-debuginfo", rpm:"liblapack3-debuginfo~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblapacke3", rpm:"liblapacke3~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblapacke3-debuginfo", rpm:"liblapacke3-debuginfo~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"blas-devel-32bit", rpm:"blas-devel-32bit~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lapack-devel-32bit", rpm:"lapack-devel-32bit~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lapacke-devel-32bit", rpm:"lapacke-devel-32bit~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblas3-32bit", rpm:"libblas3-32bit~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblas3-32bit-debuginfo", rpm:"libblas3-32bit-debuginfo~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblapack3-32bit", rpm:"liblapack3-32bit~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblapack3-32bit-debuginfo", rpm:"liblapack3-32bit-debuginfo~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblapacke3-32bit", rpm:"liblapacke3-32bit~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblapacke3-32bit-debuginfo", rpm:"liblapacke3-32bit-debuginfo~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"blas-man", rpm:"blas-man~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lapack-man", rpm:"lapack-man~3.5.0~4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"blas-devel", rpm:"blas-devel~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"blas-devel-static", rpm:"blas-devel-static~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lapack-debugsource", rpm:"lapack-debugsource~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lapack-devel", rpm:"lapack-devel~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lapack-devel-static", rpm:"lapack-devel-static~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lapacke-devel", rpm:"lapacke-devel~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lapacke-devel-static", rpm:"lapacke-devel-static~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblas3", rpm:"libblas3~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblas3-debuginfo", rpm:"libblas3-debuginfo~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblapack3", rpm:"liblapack3~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblapack3-debuginfo", rpm:"liblapack3-debuginfo~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblapacke3", rpm:"liblapacke3~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblapacke3-debuginfo", rpm:"liblapacke3-debuginfo~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"blas-man", rpm:"blas-man~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lapack-man", rpm:"lapack-man~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"blas-devel-32bit", rpm:"blas-devel-32bit~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lapack-devel-32bit", rpm:"lapack-devel-32bit~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lapacke-devel-32bit", rpm:"lapacke-devel-32bit~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblas3-32bit", rpm:"libblas3-32bit~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblas3-32bit-debuginfo", rpm:"libblas3-32bit-debuginfo~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblapack3-32bit", rpm:"liblapack3-32bit~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblapack3-32bit-debuginfo", rpm:"liblapack3-32bit-debuginfo~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblapacke3-32bit", rpm:"liblapacke3-32bit~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblapacke3-32bit-debuginfo", rpm:"liblapacke3-32bit-debuginfo~3.5.0~4.6.1", rls:"openSUSELeap15.3"))) {
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