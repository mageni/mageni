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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0478");
  script_cve_id("CVE-2022-3169", "CVE-2022-3344", "CVE-2022-3521", "CVE-2022-3643", "CVE-2022-4139", "CVE-2022-4378", "CVE-2022-45869");
  script_tag(name:"creation_date", value:"2022-12-19 04:12:36 +0000 (Mon, 19 Dec 2022)");
  script_version("2022-12-19T04:12:36+0000");
  script_tag(name:"last_modification", value:"2022-12-19 04:12:36 +0000 (Mon, 19 Dec 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-12 15:27:00 +0000 (Mon, 12 Dec 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0478)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0478");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0478.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31261");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.80");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.81");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.82");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2022-0478 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 5.15.82 and fixes at least the
following security issues:

A flaw was found in the Linux kernel. A denial of service flaw may occur
if there is a consecutive request of the NVME_IOCTL_RESET and the
NVME_IOCTL_SUBSYS_RESET through the device file of the driver, resulting
in a PCIe link disconnect (CVE-2022-3169).

A flaw was found in the KVM's AMD nested virtualization (SVM). A malicious
L1 guest could purposely fail to intercept the shutdown of a cooperative
nested guest (L2), possibly leading to a page fault and kernel panic in
the host (L0) (CVE-2022-3344).

A vulnerability has been found in Linux Kernel function kcm_tx_work of the
file net/kcm/kcmsock.c of the component kcm. The manipulation leads to race
condition (CVE-2022-3521).

An incorrect TLB flush issue was found in the Linux kernel's GPU i915 kernel
driver, potentially leading to random memory corruption or data leaks. This
flaw could allow a local user to crash the system or escalate their
privileges on the system (CVE-2022-4139).

A stack overflow flaw was found in the Linux kernel's SYSCTL subsystem in
how a user changes certain kernel parameters and variables. This flaw
allows a local user to crash or potentially escalate their privileges on the
system (CVE-2022-4378).

A race condition in the x86 KVM subsystem in the Linux kernel allows guest
OS users to cause a denial of service (host OS crash or host OS memory
corruption) when nested virtualisation and the TDP MMU are enabled
(CVE-2022-45869).

For other upstream fixes in this update, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.15.82-1.mga8", rpm:"kernel-linus-5.15.82-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.15.82-1.mga8", rpm:"kernel-linus-devel-5.15.82-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.15.82~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.15.82-1.mga8", rpm:"kernel-linus-source-5.15.82-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.15.82~1.mga8", rls:"MAGEIA8"))) {
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
