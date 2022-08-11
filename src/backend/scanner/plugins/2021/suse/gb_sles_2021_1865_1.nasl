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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1865.1");
  script_cve_id("CVE-2020-36322", "CVE-2021-28950", "CVE-2021-29154");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:37 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-06-18T08:29:57+0000");
  script_tag(name:"last_modification", value:"2021-06-28 10:25:26 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-23 02:15:00 +0000 (Wed, 23 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1865-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1865-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211865-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 35 for SLE 12 SP3)' package(s) announced via the SUSE-SU-2021:1865-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 4.4.180-94_130 fixes several issues.

The following security issues were fixed:

Fix a kernel warning during sysfs read (bsc#1186235)

CVE-2020-36322: An issue was discovered in the FUSE filesystem
 implementation in the Linux kernel aka CID-5d069dbe8aaf.
 fuse_do_getattr() calls make_bad_inode() in inappropriate situations,
 causing a system crash. NOTE: the original fix for this vulnerability
 was incomplete, and its incompleteness is tracked as CVE-2021-28950
 (bsc#1184952).

CVE-2021-29154: BPF JIT compilers in the Linux kernel have incorrect
 computation of branch displacements, allowing them to execute arbitrary
 code within the kernel context. This affects arch/x86/net/bpf_jit_comp.c
 and arch/x86/net/bpf_jit_comp32.c (bsc#1184710)");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 35 for SLE 12 SP3)' package(s) on SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server 12-SP3");

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

if(release == "SLES12.0SP3") {
  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_121-default", rpm:"kgraft-patch-4_4_180-94_121-default~10~2.2", rls:"SLES12.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_121-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_121-default-debuginfo~10~2.2", rls:"SLES12.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_124-default", rpm:"kgraft-patch-4_4_180-94_124-default~10~2.2", rls:"SLES12.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_124-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_124-default-debuginfo~10~2.2", rls:"SLES12.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_127-default", rpm:"kgraft-patch-4_4_180-94_127-default~10~2.2", rls:"SLES12.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_127-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_127-default-debuginfo~10~2.2", rls:"SLES12.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_130-default", rpm:"kgraft-patch-4_4_180-94_130-default~9~2.2", rls:"SLES12.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_130-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_130-default-debuginfo~9~2.2", rls:"SLES12.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_135-default", rpm:"kgraft-patch-4_4_180-94_135-default~7~2.2", rls:"SLES12.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_135-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_135-default-debuginfo~7~2.2", rls:"SLES12.0SP3"))){
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
