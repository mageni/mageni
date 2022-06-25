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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0392");
  script_cve_id("CVE-2020-12351", "CVE-2020-12352", "CVE-2020-14385", "CVE-2020-14386", "CVE-2020-14390", "CVE-2020-24490", "CVE-2020-25211", "CVE-2020-25221", "CVE-2020-25284", "CVE-2020-25285", "CVE-2020-25641", "CVE-2020-25643", "CVE-2020-25645");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-08 16:15:00 +0000 (Thu, 08 Apr 2021)");

  script_name("Mageia: Security Advisory (MGASA-2020-0392)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0392");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0392.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27443");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2020-14385");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2020-14386");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2020-14390");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2020-25211");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2020-25221");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2020-25284");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2020-25285");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2020-25641");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2020-25643");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2020-25645");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/CVE-2020-12351");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/CVE-2020-12352");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/CVE-2020-24490");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kmod-virtualbox, kmod-xtables-addons, xtables-addons' package(s) announced via the MGASA-2020-0392 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the way the Linux kernel Bluetooth implementation handled
L2CAP packets with A2MP CID. A remote attacker in adjacent range could use
this flaw to crash the system causing denial of service or potentially execute
arbitrary code on the system by sending a specially crafted L2CAP packet. The
highest threat from this vulnerability is to data confidentiality and
integrity as well as system availability (CVE-2020-12351).

An information leak flaw was found in the way the Linux kernel's Bluetooth
stack implementation handled initialization of stack memory when handling
certain AMP packets. A remote attacker in adjacent range could use this flaw
to leak small portions of stack memory on the system by sending a specially
crafted AMP packets. The highest threat from this vulnerability is to data
confidentiality (CVE-2020-12352).

A flaw was found in the Linux kernel before 5.9-rc4. A failure of the file
system metadata validator in XFS can cause an inode with a valid,
user-creatable extended attribute to be flagged as corrupt. This can lead to
the filesystem being shutdown, or otherwise rendered inaccessible until it is
remounted, leading to a denial of service. The highest threat from this
vulnerability is to system availability (CVE-2020-14385).

A flaw was found in the Linux kernel before 5.9-rc4. Memory corruption can be
exploited to gain root privileges from unprivileged processes. The highest
threat from this vulnerability is to data confidentiality and integrity
(CVE-2020-14386).

A flaw was found in the Linux kernel in versions before 5.9-rc6. When changing
screen size, an out-of-bounds memory write can occur leading to memory
corruption or a denial of service. Due to the nature of the flaw, privilege
escalation cannot be fully ruled out (CVE-2020-14390).

A heap buffer overflow flaw was found in the way the Linux kernel's Bluetooth
implementation processed extended advertising report events. This flaw allows
a remote attacker in an adjacent range to crash the system, causing a denial
of service or to potentially execute arbitrary code on the system by sending a
specially crafted Bluetooth packet. The highest threat from this vulnerability
is to confidentiality, integrity, as well as system availability
(CVE-2020-24490).

In the Linux kernel through 5.8.7, local attackers able to inject conntrack
netlink configuration could overflow a local buffer, causing crashes or
triggering use of incorrect protocol numbers in ctnetlink_parse_tuple_filter
in net/netfilter/nf_conntrack_netlink.c (CVE-2020-25211).

get_gate_page in mm/gup.c in the Linux kernel 5.7.x and 5.8.x before 5.8.7
allows privilege escalation because of incorrect reference counting (caused by
gate page mishandling) of the struct page that backs the vsyscall page. The
result is a refcount underflow. This can be triggered by any 64-bit process
that can use ptrace() or process_vm_readv() ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, kmod-virtualbox, kmod-xtables-addons, xtables-addons' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.7.19~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~5.7.19~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~5.7.19~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-xtables-addons", rpm:"dkms-xtables-addons~3.11~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iptaccount", rpm:"iptaccount~3.11~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.7.19~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-5.7.19-3.mga7", rpm:"kernel-desktop-5.7.19-3.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-5.7.19-3.mga7", rpm:"kernel-desktop-devel-5.7.19-3.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~5.7.19~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~5.7.19~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-5.7.19-3.mga7", rpm:"kernel-desktop586-5.7.19-3.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-5.7.19-3.mga7", rpm:"kernel-desktop586-devel-5.7.19-3.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~5.7.19~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~5.7.19~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~5.7.19~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-5.7.19-3.mga7", rpm:"kernel-server-5.7.19-3.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-5.7.19-3.mga7", rpm:"kernel-server-devel-5.7.19-3.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~5.7.19~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~5.7.19~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-5.7.19-3.mga7", rpm:"kernel-source-5.7.19-3.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~5.7.19~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~5.7.19~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~6.0.24~6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~3.11~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64account-devel", rpm:"lib64account-devel~3.11~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64account0", rpm:"lib64account0~3.11~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf-devel", rpm:"lib64bpf-devel~5.7.19~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf0", rpm:"lib64bpf0~5.7.19~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaccount-devel", rpm:"libaccount-devel~3.11~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaccount0", rpm:"libaccount0~3.11~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf-devel", rpm:"libbpf-devel~5.7.19~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf0", rpm:"libbpf0~5.7.19~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~5.7.19~3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.7.19-desktop-3.mga7", rpm:"virtualbox-kernel-5.7.19-desktop-3.mga7~6.0.24~6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.7.19-desktop586-3.mga7", rpm:"virtualbox-kernel-5.7.19-desktop586-3.mga7~6.0.24~6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.7.19-server-3.mga7", rpm:"virtualbox-kernel-5.7.19-server-3.mga7~6.0.24~6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~6.0.24~6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~6.0.24~6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~6.0.24~6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons", rpm:"xtables-addons~3.11~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.7.19-desktop-3.mga7", rpm:"xtables-addons-kernel-5.7.19-desktop-3.mga7~3.11~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.7.19-desktop586-3.mga7", rpm:"xtables-addons-kernel-5.7.19-desktop586-3.mga7~3.11~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.7.19-server-3.mga7", rpm:"xtables-addons-kernel-5.7.19-server-3.mga7~3.11~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~3.11~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~3.11~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~3.11~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-geoip", rpm:"xtables-geoip~3.11~1.mga7", rls:"MAGEIA7"))) {
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
