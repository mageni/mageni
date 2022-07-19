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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2054");
  script_cve_id("CVE-2020-29569", "CVE-2021-0938", "CVE-2021-22600", "CVE-2021-28711", "CVE-2021-28712", "CVE-2021-28713", "CVE-2021-33098", "CVE-2021-3772", "CVE-2021-39633", "CVE-2021-39685", "CVE-2021-39698", "CVE-2021-4155", "CVE-2021-4159", "CVE-2021-4197", "CVE-2021-4203", "CVE-2021-44733", "CVE-2021-45485", "CVE-2022-0322", "CVE-2022-0487", "CVE-2022-0492", "CVE-2022-0617", "CVE-2022-0847", "CVE-2022-1011", "CVE-2022-22942", "CVE-2022-24448", "CVE-2022-25375", "CVE-2022-26490", "CVE-2022-26966", "CVE-2022-27223", "CVE-2022-27666");
  script_tag(name:"creation_date", value:"2022-07-14 09:59:54 +0000 (Thu, 14 Jul 2022)");
  script_version("2022-07-14T09:59:54+0000");
  script_tag(name:"last_modification", value:"2022-07-14 09:59:54 +0000 (Thu, 14 Jul 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-22 16:12:00 +0000 (Tue, 22 Mar 2022)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2022-2054)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2054");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2054");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2022-2054 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the sctp_make_strreset_req function in net/sctp/sm_make_chunk.c in the SCTP network protocol in the Linux kernel with a local user privilege access. In this flaw, an attempt to use more buffer than is allocated triggers a BUG_ON issue, leading to a denial of service (DOS).(CVE-2022-0322)

An issue was discovered in the Linux kernel through 5.10.1, as used with Xen through 4.14.x. The Linux kernel PV block backend expects the kernel thread handler to reset ring->xenblkd to NULL when stopped. However, the handler may not have time to run if the frontend quickly toggles between the states connect and disconnect. As a consequence, the block backend may re-use a pointer after it was freed. A misbehaving guest can trigger a dom0 crash by continuously connecting / disconnecting a block frontend. Privilege escalation and information leaks cannot be ruled out. This only affects systems with a Linux blkback.(CVE-2020-29569)

Improper input validation in the Intel(R) Ethernet ixgbe driver for Linux before version 3.17.3 may allow an authenticated user to potentially enable denial of service via local access.(CVE-2021-33098)

An information leak flaw was found in the Linux kernel's IPv6 implementation in the __ipv6_select_ident in net/ipv6/output_core.c function. The use of a small hash table in IP ID generation allows a remote attacker to reveal sensitive information.(CVE-2021-45485)

A use-after-free read flaw was found in sock_getsockopt() in net/core/sock.c due to SO_PEERCRED and SO_PEERGROUPS race with listen() (and connect()) in the Linux kernel. In this flaw, an attacker with a user privileges may crash the system or leak internal kernel information.(CVE-2021-4203)

A data leak flaw was found in the way XFS_IOC_ALLOCSP IOCTL in the XFS filesystem allowed for size increase of files with unaligned size. A local attacker could use this flaw to leak data on the XFS filesystem otherwise not accessible to them.(CVE-2021-4155)

A denial of service flaw for virtual machine guests in the Linux kernel's Xen hypervisor subsystem was found in the way users call some interrupts with high frequency from one of the guests.
A local user could use this flaw to starve the resources resulting in a denial of service.(CVE-2021-28713)

A denial of service flaw for virtual machine guests in the Linux kernel's Xen hypervisor subsystem was found in the way users call some interrupts with high frequency from one of the guests.
A local user could use this flaw to starve the resources resulting in a denial of service.(CVE-2021-28711)

A denial of service flaw for virtual machine guests in the Linux kernel's Xen hypervisor subsystem was found in the way users call some interrupts with high frequency from one of the guests.
A local user could use this flaw to starve the resources resulting in a denial of service.(CVE-2021-28712)

An unprivileged write to the file handler flaw in the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization release 2.10.1.");

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

if(release == "EULEROSVIRT-2.10.1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2202.2.0.h1064.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2202.2.0.h1064.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2202.2.0.h1064.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
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
