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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.14630.1");
  script_cve_id("CVE-2019-16746", "CVE-2019-20934", "CVE-2020-0404", "CVE-2020-0431", "CVE-2020-0465", "CVE-2020-11668", "CVE-2020-14331", "CVE-2020-14353", "CVE-2020-14381", "CVE-2020-14390", "CVE-2020-15436", "CVE-2020-15437", "CVE-2020-25211", "CVE-2020-25284", "CVE-2020-25285", "CVE-2020-25643", "CVE-2020-25656", "CVE-2020-25668", "CVE-2020-25669", "CVE-2020-27068", "CVE-2020-27777", "CVE-2020-27786", "CVE-2020-28915", "CVE-2020-28974", "CVE-2020-29660", "CVE-2020-29661", "CVE-2020-36158", "CVE-2020-4788", "CVE-2021-3347");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:43 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-06-18T08:30:05+0000");
  script_tag(name:"last_modification", value:"2021-06-28 10:25:26 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:14630-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4|SLES11\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:14630-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-202114630-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:14630-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:


CVE-2021-3347: A use-after-free was discovered in the PI futexes during
 fault handling, allowing local users to execute code in the kernel
 (bnc#1181349).

CVE-2020-0465: Fixed multiple missing bounds checks in hid-multitouch.c
 that could have led to local privilege escalation (bnc#1180029).

CVE-2020-25211: Fixed a flaw where a local attacker was able to inject
 conntrack netlink configuration that could cause a denial of service or
 trigger the use of incorrect protocol numbers in
 ctnetlink_parse_tuple_filter (bnc#1176395).

CVE-2020-14390: Fixed an out-of-bounds memory write leading to memory
 corruption or a denial of service when changing screen size
 (bnc#1176235).

CVE-2020-25284: Fixed an incomplete permission checking for access to
 rbd devices, which could have been leveraged by local attackers to map
 or unmap rbd block devices (bsc#1176482).

CVE-2020-15436: Fixed a use after free vulnerability in fs/block_dev.c
 which could have allowed local users to gain privileges or cause a
 denial of service (bsc#1179141).

CVE-2020-14331: Fixed a missing check in vgacon scrollback handling
 (bsc#1174205).

CVE-2020-14353: Fixed an issue where keys - for keyctl prevent creating
 a different user's keyrings (bsc#1174993).

CVE-2020-14381: Fixed requeue paths such that filp was valid when
 dropping the references (bsc#1176011).

CVE-2020-27068: Fixed an out-of-bounds read due to a missing bounds
 check in the nl80211_policy policy of nl80211.c (bnc#1180086).

CVE-2020-27777: Fixed a privilege escalation in the Run-Time Abstraction
 Services (RTAS) interface, affecting guests running on top of PowerVM or
 KVM hypervisors (bnc#1179107).

CVE-2020-27786: Fixed an out-of-bounds write in the MIDI implementation
 (bnc#1179601).

CVE-2020-29660: Fixed a locking inconsistency in the tty subsystem that
 may have allowed a read-after-free attack against TIOCGSID (bnc#1179745).

CVE-2020-29661: Fixed a locking issue in the tty subsystem that allowed
 a use-after-free attack against TIOCSPGRP (bsc#1179745).

CVE-2020-28974: Fixed a slab-out-of-bounds read in fbcon which could
 have been used by local attackers to read privileged information or
 potentially crash the kernel (bsc#1178589).

CVE-2020-28915: Fixed a buffer over-read in the fbcon code which could
 have been used by local attackers to read kernel memory (bsc#1178886).

CVE-2020-25669: Fixed a use-after-free read in sunkbd_reinit()
 (bsc#1178182).

CVE-2020-25285: A race condition between hugetlb sysctl handlers in
 mm/hugetlb.c could be used by local attackers to corrupt memory, cause a
 NULL pointer dereference, or possibly have unspecified other impact
 (bnc#1176485 ).

CVE-2020-15437: Fixed a null pointer dereference which could have
 allowed local users to cause a denial of service ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server 11, SUSE Linux Enterprise Debuginfo 11-SP4");

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

if(release == "SLES11.0SP4") {
  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem", rpm:"kernel-bigmem~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-base", rpm:"kernel-bigmem-base~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-devel", rpm:"kernel-bigmem-devel~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~108.120.1", rls:"SLES11.0SP4"))){
    report += res;
  }


  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0") {
  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~108.120.1", rls:"SLES11.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~108.120.1", rls:"SLES11.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~108.120.1", rls:"SLES11.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~108.120.1", rls:"SLES11.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~108.120.1", rls:"SLES11.0"))){
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
