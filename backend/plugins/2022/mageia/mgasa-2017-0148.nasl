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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0148");
  script_cve_id("CVE-2016-6213", "CVE-2016-7913", "CVE-2016-7917", "CVE-2016-8632", "CVE-2016-9083", "CVE-2016-9084", "CVE-2016-9120", "CVE-2016-9604", "CVE-2017-2671", "CVE-2017-6001", "CVE-2017-6951", "CVE-2017-7308", "CVE-2017-7472", "CVE-2017-7645", "CVE-2017-7895");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2017-0148)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0148");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0148.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20860");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.60");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.61");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.62");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.63");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.64");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.65");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.66");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.67");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.68");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2017-0148 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 4.4.68 and fixes at least
the following security issues:

fs/namespace.c in the Linux kernel before 4.9 does not restrict how many
mounts may exist in a mount namespace, which allows local users to cause
a denial of service (memory consumption and deadlock) via MS_BIND mount
system calls, as demonstrated by a loop that triggers exponential growth
in the number of mounts (CVE-2016-6213).

The xc2028_set_config function in drivers/media/tuners/tuner-xc2028.c in
the Linux kernel before 4.6 allows local users to gain privileges or cause
a denial of service (use-after-free) via vectors involving omission of the
firmware name from a certain data structure (CVE-2016-7913).

The nfnetlink_rcv_batch function in net/netfilter/nfnetlink.c in the Linux
kernel before 4.5 does not check whether a batch message's length field is
large enough, which allows local users to obtain sensitive information from
kernel memory or cause a denial of service (infinite loop or out-of-bounds
read) by leveraging the CAP_NET_ADMIN capability (CVE-2016-7917).

The tipc_msg_build function in net/tipc/msg.c in the Linux kernel through
4.8.11 does not validate the relationship between the minimum fragment
length and the maximum packet size, which allows local users to gain
privileges or cause a denial of service (heap-based buffer overflow) by
leveraging the CAP_NET_ADMIN capability (CVE-2016-8632).

drivers/vfio/pci/vfio_pci.c in the Linux kernel through 4.8.11 allows local
users to bypass integer overflow checks, and cause a denial of service
(memory corruption) or have unspecified other impact, by leveraging access
to a vfio PCI device file for a VFIO_DEVICE_SET_IRQS ioctl call, aka a
'state machine confusion bug' (CVE-2016-9083).

drivers/vfio/pci/vfio_pci_intrs.c in the Linux kernel through 4.8.11
misuses the kzalloc function, which allows local users to cause a denial
of service (integer overflow) or have unspecified other impact by
leveraging access to a vfio PCI device file (CVE-2016-9084).

It was discovered that root can gain direct access to an internal keyring,
such as '.builtin_trusted_keys' upstream, by joining it as its session
keyring. This allows root to bypass module signature verification by adding
a new public key of its own devising to the keyring (CVE-2016-9604).

The ping_unhash function in net/ipv4/ping.c in the Linux kernel through
4.10.8 is too late in obtaining a certain lock and consequently cannot
ensure that disconnect function calls are safe, which allows local users
to cause a denial of service (panic) by leveraging access to the protocol
value of IPPROTO_ICMP in a socket system call (CVE-2017-2671).

Race condition in kernel/events/core.c in the Linux kernel before 4.9.7
allows local users to gain privileges via a crafted application that makes
concurrent perf_event_open system calls for moving a software group into a
hardware ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-4.4.68-1.mga5", rpm:"kernel-linus-4.4.68-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~4.4.68~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-4.4.68-1.mga5", rpm:"kernel-linus-devel-4.4.68-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~4.4.68~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~4.4.68~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~4.4.68~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-4.4.68-1.mga5", rpm:"kernel-linus-source-4.4.68-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~4.4.68~1.mga5", rls:"MAGEIA5"))) {
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
