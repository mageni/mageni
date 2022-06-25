# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852436");
  script_version("2019-04-22T07:09:02+0000");
  script_cve_id("CVE-2018-19665", "CVE-2018-19961", "CVE-2018-19962", "CVE-2018-19965",
                "CVE-2018-19966", "CVE-2018-19967", "CVE-2019-6778", "CVE-2019-9824");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-04-22 07:09:02 +0000 (Mon, 22 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-18 02:01:09 +0000 (Thu, 18 Apr 2019)");
  script_name("openSUSE Update for xen openSUSE-SU-2019:1226-1 (xen)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00072.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the openSUSE-SU-2019:1226_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

  Security issues fixed:

  - CVE-2018-19967: Fixed HLE constructs that allowed guests to lock up the
  host, resulting in a Denial of Service (DoS). (XSA-282) (bsc#1114988)

  - CVE-2019-6778: Fixed a heap buffer overflow in tcp_emu() found in slirp
  (bsc#1123157).

  - Fixed an issue which could allow malicious or buggy guests with passed
  through PCI devices to  be able to escalate their privileges, crash the
  host, or access data belonging to other guests. Additionally memory
  leaks were also possible (bsc#1126140).

  - Fixed a race condition issue which could allow malicious PV guests to
  escalate their privilege to that
  of the hypervisor (bsc#1126141).

  - Fixed an issue which could allow a malicious unprivileged guest
  userspace process to escalate its privilege to that of other userspace
  processes in the same guest and potentially thereby to that
  of the guest operating system (bsc#1126201).

  - CVE-2019-9824: Fixed an information leak in SLiRP networking
  implementation which could allow a user/process to read uninitialised
  stack memory contents (bsc#1129623).

  - CVE-2018-19961 CVE-2018-19962: Fixed insufficient TLB flushing /
  improper large page mappings with AMD IOMMUs (XSA-275)(bsc#1115040).

  - CVE-2018-19965: Fixed denial of service issue from attempting to use
  INVPCID with a non-canonical addresses (XSA-279)(bsc#1115045).

  - CVE-2018-19966: Fixed issue introduced by XSA-240 that could have caused
  conflicts with shadow paging (XSA-280)(bsc#1115047).

  - Fixed an issue which could allow malicious PV guests may cause a host
  crash or gain access to data pertaining to other guests.Additionally,
  vulnerable configurations are likely to be unstable even in the absence
  of an attack (bsc#1126198).

  - Fixed multiple access violations introduced by XENMEM_exchange hypercall
  which could allow a single PV guest to leak arbitrary amounts of memory,
  leading to a denial of service (bsc#1126192).

  - Fixed an issue which could allow malicious 64bit PV guests to cause a
  host crash (bsc#1127400).

  - Fixed an issue which could allow malicious or buggy x86 PV guest kernels
  to mount a Denial of Service attack affecting the whole system
  (bsc#1126197).

  - Fixed an issue which could allow an untrusted PV domain with access to a
  physical device to DMA into its own pagetables leading to privilege
  escalation (bsc#1126195).

  - Fixed an issue which could allow a malicious or buggy x86 PV guest
  kernels can mount a Denial of Service attack affecting the whole system
  (bsc#1126196).

  Other issues addressed:

  - ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'xen' package(s) on openSUSE Leap 42.3.");

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

if(release == "openSUSELeap42.3") {

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.9.4_02~37.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.9.4_02~37.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.9.4_02~37.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.9.4_02~37.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.9.4_02~37.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.9.4_02~37.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.9.4_02~37.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.9.4_02~37.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.9.4_02~37.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.9.4_02~37.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.9.4_02~37.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.9.4_02~37.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
