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
  script_oid("1.3.6.1.4.1.25623.1.0.854337");
  script_version("2021-12-03T04:02:27+0000");
  script_cve_id("CVE-2019-20005", "CVE-2019-20006", "CVE-2019-20007", "CVE-2019-20198", "CVE-2019-20199", "CVE-2019-20200", "CVE-2019-20201", "CVE-2019-20202", "CVE-2021-26220", "CVE-2021-26221", "CVE-2021-26222", "CVE-2021-30485", "CVE-2021-31229", "CVE-2021-31347", "CVE-2021-31348", "CVE-2021-31598");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-12-03 07:32:50 +0000 (Fri, 03 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-03 02:02:52 +0000 (Fri, 03 Dec 2021)");
  script_name("openSUSE: Security Advisory for netcdf (openSUSE-SU-2021:3873-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:3873-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TRUN6AONIMN6NUO34LRB46EYI53X2XBI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netcdf'
  package(s) announced via the openSUSE-SU-2021:3873-1 advisory.");

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

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf-gnu-hpc", rpm:"libnetcdf-gnu-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf-gnu-mpich-hpc", rpm:"libnetcdf-gnu-mpich-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf-gnu-mvapich2-hpc", rpm:"libnetcdf-gnu-mvapich2-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf-gnu-openmpi2-hpc", rpm:"libnetcdf-gnu-openmpi2-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf-gnu-openmpi3-hpc", rpm:"libnetcdf-gnu-openmpi3-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf-gnu-openmpi4-hpc", rpm:"libnetcdf-gnu-openmpi4-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18", rpm:"libnetcdf18~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-debuginfo", rpm:"libnetcdf18-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi2", rpm:"libnetcdf18-openmpi2~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi2-debuginfo", rpm:"libnetcdf18-openmpi2-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi3", rpm:"libnetcdf18-openmpi3~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi3-debuginfo", rpm:"libnetcdf18-openmpi3-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi4", rpm:"libnetcdf18-openmpi4~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi4-debuginfo", rpm:"libnetcdf18-openmpi4-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-hpc", rpm:"libnetcdf_4_7_4-gnu-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-hpc-debuginfo", rpm:"libnetcdf_4_7_4-gnu-hpc-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-mpich-hpc", rpm:"libnetcdf_4_7_4-gnu-mpich-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-mpich-hpc-debuginfo", rpm:"libnetcdf_4_7_4-gnu-mpich-hpc-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-mvapich2-hpc", rpm:"libnetcdf_4_7_4-gnu-mvapich2-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-mvapich2-hpc-debuginfo", rpm:"libnetcdf_4_7_4-gnu-mvapich2-hpc-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-openmpi2-hpc", rpm:"libnetcdf_4_7_4-gnu-openmpi2-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-openmpi2-hpc-debuginfo", rpm:"libnetcdf_4_7_4-gnu-openmpi2-hpc-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-openmpi3-hpc", rpm:"libnetcdf_4_7_4-gnu-openmpi3-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-openmpi3-hpc-debuginfo", rpm:"libnetcdf_4_7_4-gnu-openmpi3-hpc-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-openmpi4-hpc", rpm:"libnetcdf_4_7_4-gnu-openmpi4-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf_4_7_4-gnu-openmpi4-hpc-debuginfo", rpm:"libnetcdf_4_7_4-gnu-openmpi4-hpc-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf", rpm:"netcdf~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-debuginfo", rpm:"netcdf-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-debugsource", rpm:"netcdf-debugsource~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-devel", rpm:"netcdf-devel~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-devel-data", rpm:"netcdf-devel-data~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-devel-debuginfo", rpm:"netcdf-devel-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-devel-static", rpm:"netcdf-devel-static~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi2", rpm:"netcdf-openmpi2~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi2-debuginfo", rpm:"netcdf-openmpi2-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi2-debugsource", rpm:"netcdf-openmpi2-debugsource~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi2-devel", rpm:"netcdf-openmpi2-devel~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi2-devel-debuginfo", rpm:"netcdf-openmpi2-devel-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi2-devel-static", rpm:"netcdf-openmpi2-devel-static~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi3", rpm:"netcdf-openmpi3~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi3-debuginfo", rpm:"netcdf-openmpi3-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi3-debugsource", rpm:"netcdf-openmpi3-debugsource~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi3-devel", rpm:"netcdf-openmpi3-devel~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi3-devel-debuginfo", rpm:"netcdf-openmpi3-devel-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi3-devel-static", rpm:"netcdf-openmpi3-devel-static~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi4", rpm:"netcdf-openmpi4~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi4-debuginfo", rpm:"netcdf-openmpi4-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi4-debugsource", rpm:"netcdf-openmpi4-debugsource~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi4-devel", rpm:"netcdf-openmpi4-devel~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi4-devel-debuginfo", rpm:"netcdf-openmpi4-devel-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-openmpi4-devel-static", rpm:"netcdf-openmpi4-devel-static~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-hpc", rpm:"netcdf_4_7_4-gnu-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-hpc-debuginfo", rpm:"netcdf_4_7_4-gnu-hpc-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-hpc-debugsource", rpm:"netcdf_4_7_4-gnu-hpc-debugsource~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-hpc-devel", rpm:"netcdf_4_7_4-gnu-hpc-devel~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-hpc-devel-debuginfo", rpm:"netcdf_4_7_4-gnu-hpc-devel-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-hpc-devel-static", rpm:"netcdf_4_7_4-gnu-hpc-devel-static~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mpich-hpc", rpm:"netcdf_4_7_4-gnu-mpich-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mpich-hpc-debuginfo", rpm:"netcdf_4_7_4-gnu-mpich-hpc-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mpich-hpc-debugsource", rpm:"netcdf_4_7_4-gnu-mpich-hpc-debugsource~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mpich-hpc-devel", rpm:"netcdf_4_7_4-gnu-mpich-hpc-devel~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mpich-hpc-devel-debuginfo", rpm:"netcdf_4_7_4-gnu-mpich-hpc-devel-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mpich-hpc-devel-static", rpm:"netcdf_4_7_4-gnu-mpich-hpc-devel-static~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mvapich2-hpc", rpm:"netcdf_4_7_4-gnu-mvapich2-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mvapich2-hpc-debuginfo", rpm:"netcdf_4_7_4-gnu-mvapich2-hpc-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mvapich2-hpc-debugsource", rpm:"netcdf_4_7_4-gnu-mvapich2-hpc-debugsource~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mvapich2-hpc-devel", rpm:"netcdf_4_7_4-gnu-mvapich2-hpc-devel~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mvapich2-hpc-devel-debuginfo", rpm:"netcdf_4_7_4-gnu-mvapich2-hpc-devel-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-mvapich2-hpc-devel-static", rpm:"netcdf_4_7_4-gnu-mvapich2-hpc-devel-static~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi2-hpc", rpm:"netcdf_4_7_4-gnu-openmpi2-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi2-hpc-debuginfo", rpm:"netcdf_4_7_4-gnu-openmpi2-hpc-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi2-hpc-debugsource", rpm:"netcdf_4_7_4-gnu-openmpi2-hpc-debugsource~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi2-hpc-devel", rpm:"netcdf_4_7_4-gnu-openmpi2-hpc-devel~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi2-hpc-devel-debuginfo", rpm:"netcdf_4_7_4-gnu-openmpi2-hpc-devel-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi2-hpc-devel-static", rpm:"netcdf_4_7_4-gnu-openmpi2-hpc-devel-static~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi3-hpc", rpm:"netcdf_4_7_4-gnu-openmpi3-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi3-hpc-debuginfo", rpm:"netcdf_4_7_4-gnu-openmpi3-hpc-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi3-hpc-debugsource", rpm:"netcdf_4_7_4-gnu-openmpi3-hpc-debugsource~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi3-hpc-devel", rpm:"netcdf_4_7_4-gnu-openmpi3-hpc-devel~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi3-hpc-devel-debuginfo", rpm:"netcdf_4_7_4-gnu-openmpi3-hpc-devel-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi3-hpc-devel-static", rpm:"netcdf_4_7_4-gnu-openmpi3-hpc-devel-static~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi4-hpc", rpm:"netcdf_4_7_4-gnu-openmpi4-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi4-hpc-debuginfo", rpm:"netcdf_4_7_4-gnu-openmpi4-hpc-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi4-hpc-debugsource", rpm:"netcdf_4_7_4-gnu-openmpi4-hpc-debugsource~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi4-hpc-devel", rpm:"netcdf_4_7_4-gnu-openmpi4-hpc-devel~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi4-hpc-devel-debuginfo", rpm:"netcdf_4_7_4-gnu-openmpi4-hpc-devel-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf_4_7_4-gnu-openmpi4-hpc-devel-static", rpm:"netcdf_4_7_4-gnu-openmpi4-hpc-devel-static~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-32bit", rpm:"libnetcdf18-32bit~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-32bit-debuginfo", rpm:"libnetcdf18-32bit-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi2-32bit", rpm:"libnetcdf18-openmpi2-32bit~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi2-32bit-debuginfo", rpm:"libnetcdf18-openmpi2-32bit-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi3-32bit", rpm:"libnetcdf18-openmpi3-32bit~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi3-32bit-debuginfo", rpm:"libnetcdf18-openmpi3-32bit-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi4-32bit", rpm:"libnetcdf18-openmpi4-32bit~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetcdf18-openmpi4-32bit-debuginfo", rpm:"libnetcdf18-openmpi4-32bit-debuginfo~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-hpc", rpm:"netcdf-gnu-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-hpc-devel", rpm:"netcdf-gnu-hpc-devel~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-mpich-hpc", rpm:"netcdf-gnu-mpich-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-mpich-hpc-devel", rpm:"netcdf-gnu-mpich-hpc-devel~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-mvapich2-hpc", rpm:"netcdf-gnu-mvapich2-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-mvapich2-hpc-devel", rpm:"netcdf-gnu-mvapich2-hpc-devel~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-openmpi2-hpc", rpm:"netcdf-gnu-openmpi2-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-openmpi2-hpc-devel", rpm:"netcdf-gnu-openmpi2-hpc-devel~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-openmpi3-hpc", rpm:"netcdf-gnu-openmpi3-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-openmpi3-hpc-devel", rpm:"netcdf-gnu-openmpi3-hpc-devel~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-openmpi4-hpc", rpm:"netcdf-gnu-openmpi4-hpc~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcdf-gnu-openmpi4-hpc-devel", rpm:"netcdf-gnu-openmpi4-hpc-devel~4.7.4~4.3.2", rls:"openSUSELeap15.3"))) {
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
