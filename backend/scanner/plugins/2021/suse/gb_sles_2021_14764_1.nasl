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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.14764.1");
  script_cve_id("CVE-2020-24586", "CVE-2020-24587", "CVE-2020-24588", "CVE-2020-26139", "CVE-2020-36386", "CVE-2021-0512", "CVE-2021-29154", "CVE-2021-32399", "CVE-2021-34693");
  script_tag(name:"creation_date", value:"2021-07-14 02:21:14 +0000 (Wed, 14 Jul 2021)");
  script_version("2021-07-14T02:21:14+0000");
  script_tag(name:"last_modification", value:"2021-07-14 10:38:42 +0000 (Wed, 14 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-23 18:04:00 +0000 (Wed, 23 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:14764-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4|SLES11\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:14764-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-202114764-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:14764-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2021-0512: Fixed a possible out of bounds write due to a heap buffer
 overflow in __hidinput_change_resolution_multipliers. This could lead to
 local escalation of privilege with no additional execution privileges
 needed. User interaction is not needed for exploitation. (bsc#1187595)

CVE-2021-34693: Fixed a bug in net/can/bcm.c which could allow local
 users to obtain sensitive information from kernel stack memory because
 parts of a data structure are uninitialized. (bsc#1187452)

CVE-2020-36386: Fixed an out-of-bounds read in
 hci_extended_inquiry_result_evt. (bsc#1187038)

CVE-2020-24588: Fixed a bug that could allow an adversary to abuse
 devices that support receiving non-SSP A-MSDU frames to inject arbitrary
 network packets. (bsc#1185861 bsc#1185863)

CVE-2021-29154: Fixed an incorrect computation of branch displacements
 in the BPF JIT compilers, which could allow to execute arbitrary code
 within the kernel context. (bsc#1184391)

CVE-2021-32399: Fixed a race condition in net/bluetooth/hci_request.c
 for removal of the HCI controller. (bsc#1184611)

CVE-2020-24586: Fixed a bug that, under the right circumstances, allows
 to inject arbitrary network packets and/or exfiltrate user data when
 another device sends fragmented frames encrypted using WEP, CCMP, or
 GCMP. (bsc#1185859 bsc#1185863)

CVE-2020-26139: Fixed a bug that allows an Access Point (AP) to forward
 EAPOL frames to other clients even though the sender has not yet
 successfully authenticated. This might be abused in projected Wi-Fi
 networks to launch denial-of-service attacks against connected clients
 and made it easier to exploit other vulnerabilities in connected
 clients. (bsc#1185863 bsc#1186062)

CVE-2020-24587: Fixed a bug that allows an adversary to decrypt selected
 fragments when another device sends fragmented frames and the WEP, CCMP,
 or GCMP encryption key is periodically renewed. (bsc#1185862 bsc#1185863)

The following non-security bugs were fixed:

md: do not flush workqueue unconditionally in md_open (bsc#1184081).

md: factor out a mddev_find_locked helper from mddev_find (bsc#1184081).

md: md_open returns -EBUSY when entering racing area (bsc#1184081).

md: split mddev_find (bsc#1184081).");

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
  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem", rpm:"kernel-bigmem~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-base", rpm:"kernel-bigmem-base~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-devel", rpm:"kernel-bigmem-devel~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~108.129.1", rls:"SLES11.0SP4"))){
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
  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~108.129.1", rls:"SLES11.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~108.129.1", rls:"SLES11.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~108.129.1", rls:"SLES11.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~108.129.1", rls:"SLES11.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~108.129.1", rls:"SLES11.0"))){
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
