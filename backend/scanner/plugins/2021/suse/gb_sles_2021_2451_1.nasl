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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2451.1");
  script_cve_id("CVE-2020-24586", "CVE-2020-24587", "CVE-2020-24588", "CVE-2020-26139", "CVE-2020-26141", "CVE-2020-26145", "CVE-2020-26147", "CVE-2020-26558", "CVE-2020-36385", "CVE-2020-36386", "CVE-2021-0129", "CVE-2021-0512", "CVE-2021-0605", "CVE-2021-22555", "CVE-2021-23134", "CVE-2021-32399", "CVE-2021-33034", "CVE-2021-33909", "CVE-2021-34693", "CVE-2021-3609");
  script_tag(name:"creation_date", value:"2021-07-23 02:24:38 +0000 (Fri, 23 Jul 2021)");
  script_version("2021-07-23T02:24:38+0000");
  script_tag(name:"last_modification", value:"2021-07-23 10:28:28 +0000 (Fri, 23 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 11:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2451-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2451-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212451-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:2451-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2021-22555: Fixed an heap out-of-bounds write in
 net/netfilter/x_tables.c that could allow local provilege escalation.
 (bsc#1188116)

CVE-2021-33909: Fixed an out-of-bounds write in the filesystem layer
 that allows to obtain full root privileges. (bsc#1188062)

CVE-2021-3609: Fixed a race condition in the CAN BCM networking protocol
 which allows for local privilege escalation. (bsc#1187215)

CVE-2021-0605: Fixed an out-of-bounds read which could lead to local
 information disclosure in the kernel with System execution privileges
 needed. (bsc#1187601)

CVE-2021-0512: Fixed a possible out-of-bounds write which could lead to
 local escalation of privilege with no additional execution privileges
 needed. (bsc#1187595)

CVE-2021-34693: Fixed a bug in net/can/bcm.c which could allow local
 users to obtain sensitive information from kernel stack memory because
 parts of a data structure are uninitialized. (bsc#1187452)

CVE-2020-36385: Fixed a use-after-free flaw in ucma.c which allows for
 local privilege escalation. (bsc#1187050)

CVE-2021-0129: Fixed an improper access control in BlueZ that may have
 allowed an authenticated user to potentially enable information
 disclosure via adjacent access. (bsc#1186463)

CVE-2020-26558: Fixed a flaw in the Bluetooth LE and BR/EDR secure
 pairing that could permit a nearby man-in-the-middle attacker to
 identify the Passkey used during pairing. (bsc#1179610)

CVE-2020-36386: Fixed an out-of-bounds read in
 hci_extended_inquiry_result_evt. (bsc#1187038)

CVE-2020-24588: Fixed a bug that could allow an adversary to abuse
 devices that support receiving non-SSP A-MSDU frames to inject arbitrary
 network packets. (bsc#1185861)

CVE-2021-32399: Fixed a race condition in net/bluetooth/hci_request.c
 for removal of the HCI controller. (bsc#1184611)

CVE-2021-33034: Fixed an issue in net/bluetooth/hci_event.c where a
 use-after-free leads to writing an arbitrary value. (bsc#1186111)

CVE-2020-26139: Fixed a bug that allows an Access Point (AP) to forward
 EAPOL frames to other clients even though the sender has not yet
 successfully authenticated. This might be abused in projected Wi-Fi
 networks to launch denial-of-service attacks against connected clients
 and made it easier to exploit other vulnerabilities in connected
 clients. (bsc#1186062)

CVE-2021-23134: Fixed a use After Free vulnerability in nfc sockets
 which allows local attackers to elevate their privileges. (bsc#1186060)

CVE-2020-24586: Fixed a bug that, under the right circumstances, allows
 to inject arbitrary network packets and/or exfiltrate user data when
 another device sends fragmented frames encrypted using WEP, CCMP, or
 GCMP. (bsc#1185859)

CVE-2020-26141: Fixed a flaw that could allows an adversary to inject
 and possibly ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE OpenStack Cloud Crowbar 8, SUSE OpenStack Cloud 8, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise High Availability 12-SP3, HPE Helion Openstack 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.180~94.147.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.180~94.147.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.4.180~94.147.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.4.180~94.147.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.4.180~94.147.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.180~94.147.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.180~94.147.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-kgraft", rpm:"kernel-default-kgraft~4.4.180~94.147.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_147-default", rpm:"kgraft-patch-4_4_180-94_147-default~1~4.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_147-default-debuginfo", rpm:"kgraft-patch-4_4_180-94_147-default-debuginfo~1~4.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.180~94.147.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.180~94.147.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.180~94.147.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.180~94.147.1", rls:"SLES12.0SP3"))) {
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
