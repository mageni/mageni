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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0176");
  script_cve_id("CVE-2015-8817", "CVE-2015-8818", "CVE-2016-1922", "CVE-2016-1981", "CVE-2016-2197", "CVE-2016-2198", "CVE-2016-2391", "CVE-2016-2392", "CVE-2016-2538", "CVE-2016-2841", "CVE-2016-2857", "CVE-2016-2858", "CVE-2016-3710", "CVE-2016-3712", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4020", "CVE-2016-4037");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-14 19:54:00 +0000 (Mon, 14 Dec 2020)");

  script_name("Mageia: Security Advisory (MGASA-2016-0176)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0176");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0176.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17534");
  script_xref(name:"URL", value:"http://wiki.qemu.org/ChangeLog/2.2");
  script_xref(name:"URL", value:"http://wiki.qemu.org/ChangeLog/2.3");
  script_xref(name:"URL", value:"http://wiki.qemu.org/ChangeLog/2.4");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1300771");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1283934");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2891-1/");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2974-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the MGASA-2016-0176 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated qemu packages fix security vulnerabilities:

An out-of-bounds flaw was found in the QEMU emulator built using
'address_space_translate' to map an address to a MemoryRegionSection. The
flaw could occur while doing pci_dma_read/write calls, resulting in an
out-of-bounds read-write access error. A privileged user inside a guest could
use this flaw to crash the guest instance (denial of service) (CVE-2015-8817,
CVE-2015-8818).

A NULL-pointer dereference flaw was found in the QEMU emulator built with TPR
optimization for 32-bit Windows guests support. The flaw occurs when doing
I/O-port write operations from the HMP interface. The 'current_cpu' value
remains null because it is not called from the cpu_exec() loop, and
dereferencing it results in the flaw. An attacker with access to the HMP
interface could use this flaw to crash the QEMU instance (denial of service)
(CVE-2016-1922).

It was discovered that QEMU incorrectly handled the e1000 device. An
attacker inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service (CVE-2016-1981).

Zuozhi Fzz discovered that QEMU incorrectly handled IDE AHCI emulation. An
attacker inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service (CVE-2016-2197).

Zuozhi Fzz discovered that QEMU incorrectly handled USB EHCI emulation. An
attacker inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service (CVE-2016-2198).

Zuozhi Fzz discovered that QEMU incorrectly handled USB OHCI emulation
support. A privileged attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service (CVE-2016-2391).

Qinghao Tang discovered that QEMU incorrectly handled USB Net emulation
support. A privileged attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service (CVE-2016-2392).

Qinghao Tang discovered that QEMU incorrectly handled USB Net emulation
support. A privileged attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service, or possibly leak
host memory bytes (CVE-2016-2538).

Hongke Yang discovered that QEMU incorrectly handled NE2000 emulation
support. A privileged attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service (CVE-2016-2841).

Ling Liu discovered that QEMU incorrectly handled IP checksum routines. An
attacker inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service, or possibly leak host memory bytes
(CVE-2016-2857).

It was discovered that QEMU incorrectly handled the PRNG back-end support.
An attacker inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service (CVE-2016-2858).

Wei Xiao and Qinghao Tang discovered that QEMU incorrectly handled access
in the VGA module. A privileged ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.4.1~5.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~2.4.1~5.mga5", rls:"MAGEIA5"))) {
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
