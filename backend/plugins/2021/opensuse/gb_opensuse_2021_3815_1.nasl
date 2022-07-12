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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.854326");
  script_version("2021-12-03T04:02:27+0000");
  script_cve_id("CVE-2019-20005", "CVE-2019-20006", "CVE-2019-20007", "CVE-2019-20198", "CVE-2019-20199", "CVE-2019-20200", "CVE-2019-20201", "CVE-2019-20202", "CVE-2021-26220", "CVE-2021-26221", "CVE-2021-26222", "CVE-2021-30485", "CVE-2021-31229", "CVE-2021-31347", "CVE-2021-31348", "CVE-2021-31598");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-12-03 07:32:50 +0000 (Fri, 03 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-01 02:02:43 +0000 (Wed, 01 Dec 2021)");
  script_name("openSUSE: Security Advisory for netcdf (openSUSE-SU-2021:3815-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:3815-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BNULBT7RBXXDXTGAFBIJZ4GX5T4OWM7O");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netcdf'
  package(s) announced via the openSUSE-SU-2021:3815-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for netcdf fixes the following issues:

  - Fixed multiple vulnerabilities in ezXML: CVE-2019-20007, CVE-2019-20006,
       CVE-2019-20201, CVE-2019-20202, CVE-2019-20199, CVE-2019-20200,
       CVE-2019-20198, CVE-2021-26221, CVE-2021-26222, CVE-2021-30485,
       CVE-2021-31229, CVE-2021-31347, CVE-2021-31348, CVE-2021-31598
       (bsc#1191856)
          be reproduced and no patch is available upstream.");

  script_tag(name:"affected", value:"'netcdf' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf-gnu-openmpi1-hpc", rpm:"libnetcdf-gnu-openmpi1-hpc~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_6_1-gnu-hpc", rpm:"libnetcdf_4_6_1-gnu-hpc~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_6_1-gnu-hpc-debuginfo", rpm:"libnetcdf_4_6_1-gnu-hpc-debuginfo~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_6_1-gnu-mpich-hpc", rpm:"libnetcdf_4_6_1-gnu-mpich-hpc~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_6_1-gnu-mpich-hpc-debuginfo", rpm:"libnetcdf_4_6_1-gnu-mpich-hpc-debuginfo~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_6_1-gnu-mvapich2-hpc", rpm:"libnetcdf_4_6_1-gnu-mvapich2-hpc~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_6_1-gnu-mvapich2-hpc-debuginfo", rpm:"libnetcdf_4_6_1-gnu-mvapich2-hpc-debuginfo~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_6_1-gnu-openmpi1-hpc", rpm:"libnetcdf_4_6_1-gnu-openmpi1-hpc~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_6_1-gnu-openmpi1-hpc-debuginfo", rpm:"libnetcdf_4_6_1-gnu-openmpi1-hpc-debuginfo~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_6_1-gnu-openmpi2-hpc", rpm:"libnetcdf_4_6_1-gnu-openmpi2-hpc~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_6_1-gnu-openmpi2-hpc-debuginfo", rpm:"libnetcdf_4_6_1-gnu-openmpi2-hpc-debuginfo~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-hpc", rpm:"netcdf_4_6_1-gnu-hpc~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-hpc-debuginfo", rpm:"netcdf_4_6_1-gnu-hpc-debuginfo~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-hpc-devel", rpm:"netcdf_4_6_1-gnu-hpc-devel~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-hpc-devel-data", rpm:"netcdf_4_6_1-gnu-hpc-devel-data~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-hpc-devel-debuginfo", rpm:"netcdf_4_6_1-gnu-hpc-devel-debuginfo~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-hpc-devel-static", rpm:"netcdf_4_6_1-gnu-hpc-devel-static~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-mpich-hpc", rpm:"netcdf_4_6_1-gnu-mpich-hpc~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-mpich-hpc-debuginfo", rpm:"netcdf_4_6_1-gnu-mpich-hpc-debuginfo~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-mpich-hpc-debugsource", rpm:"netcdf_4_6_1-gnu-mpich-hpc-debugsource~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-mpich-hpc-devel", rpm:"netcdf_4_6_1-gnu-mpich-hpc-devel~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-mpich-hpc-devel-debuginfo", rpm:"netcdf_4_6_1-gnu-mpich-hpc-devel-debuginfo~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-mpich-hpc-devel-static", rpm:"netcdf_4_6_1-gnu-mpich-hpc-devel-static~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-mvapich2-hpc", rpm:"netcdf_4_6_1-gnu-mvapich2-hpc~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-mvapich2-hpc-debuginfo", rpm:"netcdf_4_6_1-gnu-mvapich2-hpc-debuginfo~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-mvapich2-hpc-debugsource", rpm:"netcdf_4_6_1-gnu-mvapich2-hpc-debugsource~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-mvapich2-hpc-devel", rpm:"netcdf_4_6_1-gnu-mvapich2-hpc-devel~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-mvapich2-hpc-devel-debuginfo", rpm:"netcdf_4_6_1-gnu-mvapich2-hpc-devel-debuginfo~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-mvapich2-hpc-devel-static", rpm:"netcdf_4_6_1-gnu-mvapich2-hpc-devel-static~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-openmpi1-hpc", rpm:"netcdf_4_6_1-gnu-openmpi1-hpc~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-openmpi1-hpc-debuginfo", rpm:"netcdf_4_6_1-gnu-openmpi1-hpc-debuginfo~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-openmpi1-hpc-devel", rpm:"netcdf_4_6_1-gnu-openmpi1-hpc-devel~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-openmpi1-hpc-devel-debuginfo", rpm:"netcdf_4_6_1-gnu-openmpi1-hpc-devel-debuginfo~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-openmpi1-hpc-devel-static", rpm:"netcdf_4_6_1-gnu-openmpi1-hpc-devel-static~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-openmpi2-hpc", rpm:"netcdf_4_6_1-gnu-openmpi2-hpc~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-openmpi2-hpc-debuginfo", rpm:"netcdf_4_6_1-gnu-openmpi2-hpc-debuginfo~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-openmpi2-hpc-devel", rpm:"netcdf_4_6_1-gnu-openmpi2-hpc-devel~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-openmpi2-hpc-devel-debuginfo", rpm:"netcdf_4_6_1-gnu-openmpi2-hpc-devel-debuginfo~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_6_1-gnu-openmpi2-hpc-devel-static", rpm:"netcdf_4_6_1-gnu-openmpi2-hpc-devel-static~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-openmpi1-hpc", rpm:"netcdf-gnu-openmpi1-hpc~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-openmpi1-hpc-devel", rpm:"netcdf-gnu-openmpi1-hpc-devel~4.6.1~10.7.2", rls:"openSUSELeap15.3"))) {
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
