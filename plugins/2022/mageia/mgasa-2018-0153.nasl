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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0153");
  script_cve_id("CVE-2017-1000256", "CVE-2017-5715", "CVE-2018-5748", "CVE-2018-6764");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 20:21:00 +0000 (Mon, 16 Nov 2020)");

  script_name("Mageia: Security Advisory (MGASA-2018-0153)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0153");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0153.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22280");
  script_xref(name:"URL", value:"https://security.libvirt.org/2017/0002.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-10/msg00018.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-10/msg00096.html");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2018:0029");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt, python-libvirt' package(s) announced via the MGASA-2018-0153 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libvirt packages fix security vulnerabilities:

In virsh, the hostname could crafted maliciously with ssh arguments, which would
be passed to ssh (bsc#1053600).

The default_tls_x509_verify (and related) parameters in qemu.conf control
whether the TLS servers in QEMU request & verify certificates from clients. This
works as a simple access control system for QEMU servers by requiring the CA to
issue certs to permitted clients. This use of client certificates is disabled by
default, since it requires extra work to issue client certificates.
Unfortunately the libvirt code was using these configuration parameters when
setting up both TLS clients and servers in QEMU. The result was that TLS clients
for character devices and disk devices had verification turned off, meaning they
would ignore any errors while validating the server certificate
(CVE-2017-1000256).

An industry-wide issue was found in the way many modern microprocessor designs
have implemented speculative execution of instructions (a commonly used
performance optimization). There are three primary variants of the issue which
differ in the way the speculative execution can be exploited. Variant
CVE-2017-5715 triggers the speculative execution by utilizing branch target
injection. It relies on the presence of a precisely-defined instruction sequence
in the privileged code as well as the fact that memory accesses may cause
allocation into the microprocessor's data cache even for speculatively executed
instructions that never actually commit (retire). As a result, an unprivileged
attacker could use this flaw to cross the syscall and guest/host boundaries and
read privileged memory by conducting targeted cache side-channel attacks
(CVE-2017-5715).

qemu/qemu_monitor.c in libvirt allows attackers to cause a denial of service
(memory consumption) via a large QEMU reply (CVE-2018-5748).

It was discovered libvirt does not properly determine the hostname on LXC
container startup, which allows local guest OS users to bypass an intended
container protection mechanism and execute arbitrary commands via a crafted NSS
module (CVE-2018-6764).");

  script_tag(name:"affected", value:"'libvirt, python-libvirt' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64virt-devel", rpm:"lib64virt-devel~3.10.0~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64virt0", rpm:"lib64virt0~3.10.0~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~3.10.0~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~3.10.0~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-docs", rpm:"libvirt-docs~3.10.0~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-utils", rpm:"libvirt-utils~3.10.0~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt0", rpm:"libvirt0~3.10.0~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libvirt", rpm:"python-libvirt~3.10.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libvirt", rpm:"python3-libvirt~3.10.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-libvirt", rpm:"wireshark-libvirt~3.10.0~1.1.mga6", rls:"MAGEIA6"))) {
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
