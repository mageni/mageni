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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3825.1");
  script_cve_id("CVE-2018-11205", "CVE-2018-13867", "CVE-2018-14031", "CVE-2018-16438", "CVE-2018-17439", "CVE-2019-8396", "CVE-2020-10812", "CVE-2021-45830", "CVE-2021-45833", "CVE-2021-46242", "CVE-2021-46244");
  script_tag(name:"creation_date", value:"2022-11-02 04:46:04 +0000 (Wed, 02 Nov 2022)");
  script_version("2022-11-02T10:12:00+0000");
  script_tag(name:"last_modification", value:"2022-11-02 10:12:00 +0000 (Wed, 02 Nov 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-28 17:20:00 +0000 (Tue, 28 Aug 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3825-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3825-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223825-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hdf5' package(s) announced via the SUSE-SU-2022:3825-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for hdf5 fixes the following issues:

 - CVE-2021-46244: Fixed division by zero leading to DoS (bsc#1195215).
 - CVE-2018-13867: Fixed out of bounds read in the function
 H5F__accum_read in H5Faccum.c (bsc#1101906).
 - CVE-2018-16438: Fixed out of bounds read in H5L_extern_query at
 H5Lexternal.c (bsc#1107069).
 - CVE-2020-10812: Fixed NULL pointer dereference (bsc#1167400).
 - CVE-2021-45830: Fixed heap buffer overflow vulnerability in
 H5F_addr_decode_len in /hdf5/src/H5Fint.c (bsc#1194375).
 - CVE-2019-8396: Fixed buffer overflow in function H5O__layout_encode
 in H5Olayout.c (bsc#1125882).
 - CVE-2018-11205: Fixed out of bounds read was discovered in
 H5VM_memcpyvv in H5VM.c (bsc#1093663).
 - CVE-2021-46242: Fixed heap-use-after free via the component
 H5AC_unpin_entry (bsc#1195212).
 - CVE-2021-45833: Fixed stack buffer overflow vulnerability
 (bsc#1194366).
 - CVE-2018-14031: Fixed heap-based buffer over-read in the function
 H5T_copy in H5T.c (bsc#1101475).
 - CVE-2018-17439: Fixed out of bounds read in the function
 H5F__accum_read in H5Faccum.c (bsc#1111598).");

  script_tag(name:"affected", value:"'hdf5' package(s) on SUSE Linux Enterprise Module for HPC 15-SP4, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-hpc", rpm:"hdf5-gnu-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-hpc-devel", rpm:"hdf5-gnu-hpc-devel~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-mpich-hpc", rpm:"hdf5-gnu-mpich-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-mpich-hpc-devel", rpm:"hdf5-gnu-mpich-hpc-devel~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-mvapich2-hpc", rpm:"hdf5-gnu-mvapich2-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-mvapich2-hpc-devel", rpm:"hdf5-gnu-mvapich2-hpc-devel~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-openmpi3-hpc", rpm:"hdf5-gnu-openmpi3-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-openmpi3-hpc-devel", rpm:"hdf5-gnu-openmpi3-hpc-devel~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-openmpi4-hpc", rpm:"hdf5-gnu-openmpi4-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-openmpi4-hpc-devel", rpm:"hdf5-gnu-openmpi4-hpc-devel~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-hpc-examples", rpm:"hdf5-hpc-examples~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_8-gnu-hpc-debuginfo", rpm:"hdf5_1_10_8-gnu-hpc-debuginfo~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_8-gnu-hpc-debugsource", rpm:"hdf5_1_10_8-gnu-hpc-debugsource~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_8-gnu-mpich-hpc-debuginfo", rpm:"hdf5_1_10_8-gnu-mpich-hpc-debuginfo~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_8-gnu-mpich-hpc-debugsource", rpm:"hdf5_1_10_8-gnu-mpich-hpc-debugsource~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_8-gnu-mvapich2-hpc-debuginfo", rpm:"hdf5_1_10_8-gnu-mvapich2-hpc-debuginfo~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_8-gnu-mvapich2-hpc-debugsource", rpm:"hdf5_1_10_8-gnu-mvapich2-hpc-debugsource~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_8-gnu-openmpi3-hpc-debuginfo", rpm:"hdf5_1_10_8-gnu-openmpi3-hpc-debuginfo~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_8-gnu-openmpi3-hpc-debugsource", rpm:"hdf5_1_10_8-gnu-openmpi3-hpc-debugsource~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_8-gnu-openmpi4-hpc-debuginfo", rpm:"hdf5_1_10_8-gnu-openmpi4-hpc-debuginfo~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5_1_10_8-gnu-openmpi4-hpc-debugsource", rpm:"hdf5_1_10_8-gnu-openmpi4-hpc-debugsource~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-hpc", rpm:"libhdf5-gnu-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-mpich-hpc", rpm:"libhdf5-gnu-mpich-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-mvapich2-hpc", rpm:"libhdf5-gnu-mvapich2-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-openmpi3-hpc", rpm:"libhdf5-gnu-openmpi3-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-openmpi4-hpc", rpm:"libhdf5-gnu-openmpi4-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-hpc", rpm:"libhdf5_cpp-gnu-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-mpich-hpc", rpm:"libhdf5_cpp-gnu-mpich-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-mvapich2-hpc", rpm:"libhdf5_cpp-gnu-mvapich2-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-openmpi3-hpc", rpm:"libhdf5_cpp-gnu-openmpi3-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-openmpi4-hpc", rpm:"libhdf5_cpp-gnu-openmpi4-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-hpc", rpm:"libhdf5_fortran-gnu-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-mpich-hpc", rpm:"libhdf5_fortran-gnu-mpich-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-mvapich2-hpc", rpm:"libhdf5_fortran-gnu-mvapich2-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-openmpi3-hpc", rpm:"libhdf5_fortran-gnu-openmpi3-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-openmpi4-hpc", rpm:"libhdf5_fortran-gnu-openmpi4-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-hpc", rpm:"libhdf5_hl-gnu-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-mpich-hpc", rpm:"libhdf5_hl-gnu-mpich-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-mvapich2-hpc", rpm:"libhdf5_hl-gnu-mvapich2-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-openmpi3-hpc", rpm:"libhdf5_hl-gnu-openmpi3-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-openmpi4-hpc", rpm:"libhdf5_hl-gnu-openmpi4-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-hpc", rpm:"libhdf5_hl_cpp-gnu-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-mpich-hpc", rpm:"libhdf5_hl_cpp-gnu-mpich-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-mvapich2-hpc", rpm:"libhdf5_hl_cpp-gnu-mvapich2-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-openmpi3-hpc", rpm:"libhdf5_hl_cpp-gnu-openmpi3-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-openmpi4-hpc", rpm:"libhdf5_hl_cpp-gnu-openmpi4-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-hpc", rpm:"libhdf5_hl_fortran-gnu-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-mpich-hpc", rpm:"libhdf5_hl_fortran-gnu-mpich-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-mvapich2-hpc", rpm:"libhdf5_hl_fortran-gnu-mvapich2-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-openmpi3-hpc", rpm:"libhdf5_hl_fortran-gnu-openmpi3-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-openmpi4-hpc", rpm:"libhdf5_hl_fortran-gnu-openmpi4-hpc~1.10.8~150400.3.3.1", rls:"SLES15.0SP4"))) {
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
