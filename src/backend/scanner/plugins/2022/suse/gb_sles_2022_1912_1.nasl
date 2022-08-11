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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1912.1");
  script_cve_id("CVE-2018-11206", "CVE-2018-14032", "CVE-2018-14033", "CVE-2018-14460", "CVE-2018-17234", "CVE-2018-17237", "CVE-2018-17432", "CVE-2018-17433", "CVE-2018-17434", "CVE-2018-17436", "CVE-2018-17437", "CVE-2018-17438", "CVE-2020-10809", "CVE-2020-10810", "CVE-2020-10811");
  script_tag(name:"creation_date", value:"2022-06-02 14:53:41 +0000 (Thu, 02 Jun 2022)");
  script_version("2022-06-02T14:53:41+0000");
  script_tag(name:"last_modification", value:"2022-06-03 10:37:36 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-06 15:17:00 +0000 (Thu, 06 Sep 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1912-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1912-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221912-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hdf5' package(s) announced via the SUSE-SU-2022:1912-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for hdf5 fixes the following issues:

Security issues fixed:

CVE-2020-10811: Fixed heap-based buffer over-read in the function
 H5O__layout_decode() located in H5Olayout.c (bsc#1167405).

CVE-2020-10810: Fixed NULL pointer dereference in the function
 H5AC_unpin_entry() located in H5AC.c (bsc#1167401).

CVE-2020-10809: Fixed heap-based buffer overflow in the function
 Decompress() located in decompress.c (bsc#1167404).

CVE-2018-17438: Fixed SIGFPE signal raise in the function
 H5D__select_io() of H5Dselect.c (bsc#1109570).

CVE-2018-17437: Fixed memory leak in the H5O_dtype_decode_helper()
 function in H5Odtype.c. (bsc#1109569).

CVE-2018-17436: Fixed issue in ReadCode() in decompress.c that allowed
 attackers to cause a denial of service via a crafted HDF5 file
 (bsc#1109568).

CVE-2018-17434: Fixed SIGFPE signal raise in function apply_filters() of
 h5repack_filters.c (bsc#1109566).

CVE-2018-17433: Fixed heap-based buffer overflow in ReadGifImageDesc()
 in gifread.c (bsc#1109565).

CVE-2018-17432: Fixed NULL pointer dereference in H5O_sdspace_encode()
 in H5Osdspace.c (bsc#1109564).

CVE-2018-17237: Fixed SIGFPE signal raise in the function
 H5D__chunk_set_info_real() (bsc#1109168).

CVE-2018-17234: Fixed memory leak in the H5O__chunk_deserialize()
 function in H5Ocache.c (bsc#1109167).

CVE-2018-14460: Fixed heap-based buffer over-read in the function
 H5O_sdspace_decode in H5Osdspace.c (bsc#1102175).

CVE-2018-14033: Fixed heap-based buffer over-read in the function
 H5O_layout_decode in H5Olayout.c (bsc#1101471).

CVE-2018-14032: Fixed heap-based buffer over-read in the function
 H5O_fill_new_decode in H5Ofill.c (bsc#1101474).

CVE-2018-11206: Fixed out of bounds read in H5O_fill_new_decode and
 H5O_fill_old_decode in H5Ofill.c (bsc#1093657).

Bugfixes:

Fix python-h5py packages built against out-of-date version of HDF5
 (bsc#1196682).

Fix netcdf-cxx4 packages built against out-of-date version of HDF5
 (bsc#1179521).");

  script_tag(name:"affected", value:"'hdf5' package(s) on SUSE Linux Enterprise Module for HPC 15-SP3, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-hpc", rpm:"hdf5-gnu-hpc~1.10.8~150300.4.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-hpc-devel", rpm:"hdf5-gnu-hpc-devel~1.10.8~150300.4.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-mpich-hpc", rpm:"hdf5-gnu-mpich-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-mpich-hpc-devel", rpm:"hdf5-gnu-mpich-hpc-devel~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-mvapich2-hpc", rpm:"hdf5-gnu-mvapich2-hpc~1.10.8~150300.4.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-mvapich2-hpc-devel", rpm:"hdf5-gnu-mvapich2-hpc-devel~1.10.8~150300.4.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-openmpi3-hpc", rpm:"hdf5-gnu-openmpi3-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-openmpi3-hpc-devel", rpm:"hdf5-gnu-openmpi3-hpc-devel~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-openmpi4-hpc", rpm:"hdf5-gnu-openmpi4-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-gnu-openmpi4-hpc-devel", rpm:"hdf5-gnu-openmpi4-hpc-devel~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hdf5-hpc-examples", rpm:"hdf5-hpc-examples~1.10.8~150300.4.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-hpc", rpm:"libhdf5-gnu-hpc~1.10.8~150300.4.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-mpich-hpc", rpm:"libhdf5-gnu-mpich-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-mvapich2-hpc", rpm:"libhdf5-gnu-mvapich2-hpc~1.10.8~150300.4.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-openmpi3-hpc", rpm:"libhdf5-gnu-openmpi3-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-gnu-openmpi4-hpc", rpm:"libhdf5-gnu-openmpi4-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-hpc", rpm:"libhdf5_cpp-gnu-hpc~1.10.8~150300.4.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-mpich-hpc", rpm:"libhdf5_cpp-gnu-mpich-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-mvapich2-hpc", rpm:"libhdf5_cpp-gnu-mvapich2-hpc~1.10.8~150300.4.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-openmpi3-hpc", rpm:"libhdf5_cpp-gnu-openmpi3-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_cpp-gnu-openmpi4-hpc", rpm:"libhdf5_cpp-gnu-openmpi4-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-hpc", rpm:"libhdf5_fortran-gnu-hpc~1.10.8~150300.4.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-mpich-hpc", rpm:"libhdf5_fortran-gnu-mpich-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-mvapich2-hpc", rpm:"libhdf5_fortran-gnu-mvapich2-hpc~1.10.8~150300.4.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-openmpi3-hpc", rpm:"libhdf5_fortran-gnu-openmpi3-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_fortran-gnu-openmpi4-hpc", rpm:"libhdf5_fortran-gnu-openmpi4-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-hpc", rpm:"libhdf5_hl-gnu-hpc~1.10.8~150300.4.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-mpich-hpc", rpm:"libhdf5_hl-gnu-mpich-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-mvapich2-hpc", rpm:"libhdf5_hl-gnu-mvapich2-hpc~1.10.8~150300.4.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-openmpi3-hpc", rpm:"libhdf5_hl-gnu-openmpi3-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl-gnu-openmpi4-hpc", rpm:"libhdf5_hl-gnu-openmpi4-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-hpc", rpm:"libhdf5_hl_cpp-gnu-hpc~1.10.8~150300.4.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-mpich-hpc", rpm:"libhdf5_hl_cpp-gnu-mpich-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-mvapich2-hpc", rpm:"libhdf5_hl_cpp-gnu-mvapich2-hpc~1.10.8~150300.4.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-openmpi3-hpc", rpm:"libhdf5_hl_cpp-gnu-openmpi3-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_cpp-gnu-openmpi4-hpc", rpm:"libhdf5_hl_cpp-gnu-openmpi4-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-hpc", rpm:"libhdf5_hl_fortran-gnu-hpc~1.10.8~150300.4.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-mpich-hpc", rpm:"libhdf5_hl_fortran-gnu-mpich-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-mvapich2-hpc", rpm:"libhdf5_hl_fortran-gnu-mvapich2-hpc~1.10.8~150300.4.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-openmpi3-hpc", rpm:"libhdf5_hl_fortran-gnu-openmpi3-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl_fortran-gnu-openmpi4-hpc", rpm:"libhdf5_hl_fortran-gnu-openmpi4-hpc~1.10.8~150300.4.3.2", rls:"SLES15.0SP3"))) {
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
