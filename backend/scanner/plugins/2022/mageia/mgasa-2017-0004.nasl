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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0004");
  script_cve_id("CVE-2016-8399", "CVE-2016-8645", "CVE-2016-8650", "CVE-2016-8655", "CVE-2016-9576", "CVE-2016-9756", "CVE-2016-9793", "CVE-2016-9794");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-25 01:29:00 +0000 (Fri, 25 May 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0004)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0004");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0004.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19992");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19892");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19853");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.33");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.34");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.35");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.36");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.37");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.38");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.39");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-tmb' package(s) announced via the MGASA-2017-0004 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update is based on upstream 4.4.39 and fixes at least the following
security issues:

Due to lack of size checking on ICMP header length, it is possible to
cause out-of-bounds read on stack (CVE-2016-8399)

The TCP stack in the Linux kernel before 4.8.10 mishandles skb
truncation, which allows local users to cause a denial of service
(system crash) via a crafted application that makes sendto system calls,
related to net/ipv4/tcp_ipv4.c and net/ipv6/tcp_ipv6.c (CVE-2016-8645).

The mpi_powm function in lib/mpi/mpi-pow.c in the Linux kernel through
4.8.11 does not ensure that memory is allocated for limb data, which
allows local users to cause a denial of service (stack memory corruption
and panic) via an add_key system call for an RSA key with a zero
exponent (CVE-2016-8650).

A race condition issue leading to a use-after-free flaw was found in the
way the raw packet sockets implementation in the Linux kernel networking
subsystem handled synchronization while creating the TPACKET_V3 ring
buffer. A local user able to open a raw packet socket (requires the
CAP_NET_RAW capability) could use this flaw to elevate their privileges
on the system (CVE-2016-8655).

A use-after-free vulnerability in the SCSI generic driver allows users
with write access to /dev/sg* or /dev/bsg* to elevate their privileges
(CVE-2016-9576).

Linux kernel built with the Kernel-based Virtual Machine(CONFIG_KVM)
support is vulnerable to an information leakage issue. It could occur
on x86 platform, while emulating instructions in 32bit mode. A
user/process could use this flaw to leak host kernel memory bytes
(CVE-2016-9756).

A bug in SO_{SND<pipe>RCV}BUFFORCE setsockopt() implementation allows
CAP_NET_ADMIN users to set negative sk_sndbuf or sk_rcvbuf values.
A user could use this flaw to cause various memory corruptions,
crashes and OOM (CVE-2016-9793).

A use-after-free vulnerability was found in ALSA pcm layer, which allows
local users to cause a denial of service, memory corruption, or possibly
other unspecified impact (CVE-2016-9794).

Other fixes in this update:
- fix for HID gamepad DragonRise (mga#19853)
- fix for radeon driver crashing on Dell Precision M4800 (mga#19892)

For other upstream fixes in this update, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-tmb' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb", rpm:"kernel-tmb~4.4.39~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-4.4.39-1.mga5", rpm:"kernel-tmb-desktop-4.4.39-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-4.4.39-1.mga5", rpm:"kernel-tmb-desktop-devel-4.4.39-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-latest", rpm:"kernel-tmb-desktop-devel-latest~4.4.39~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-latest", rpm:"kernel-tmb-desktop-latest~4.4.39~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-4.4.39-1.mga5", rpm:"kernel-tmb-source-4.4.39-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-latest", rpm:"kernel-tmb-source-latest~4.4.39~1.mga5", rls:"MAGEIA5"))) {
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
