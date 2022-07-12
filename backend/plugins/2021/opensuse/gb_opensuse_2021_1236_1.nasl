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
  script_oid("1.3.6.1.4.1.25623.1.0.854148");
  script_version("2021-09-22T08:01:20+0000");
  script_cve_id("CVE-2021-0089", "CVE-2021-28690", "CVE-2021-28692", "CVE-2021-28693", "CVE-2021-28694", "CVE-2021-28695", "CVE-2021-28696", "CVE-2021-28697", "CVE-2021-28698", "CVE-2021-28699", "CVE-2021-28700");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-09-22 10:15:34 +0000 (Wed, 22 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-01 17:35:00 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-08 01:01:49 +0000 (Wed, 08 Sep 2021)");
  script_name("openSUSE: Security Advisory for xen (openSUSE-SU-2021:1236-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1236-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VYJVCSKTOQY75TLGWH3HDYZAS33JTOTQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the openSUSE-SU-2021:1236-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

     Update to Xen 4.13.3 general bug fix release (bsc#1027519).

     Security issues fixed:

  - CVE-2021-28693: xen/arm: Boot modules are not scrubbed (bsc#1186428)

  - CVE-2021-28692: xen: inappropriate x86 IOMMU timeout detection /
       handling (bsc#1186429)

  - CVE-2021-0089: xen: Speculative Code Store Bypass (bsc#1186433)

  - CVE-2021-28690: xen: x86: TSX Async Abort protections not restored after
       S3 (bsc#1186434)

  - CVE-2021-28694, CVE-2021-28695, CVE-2021-28696: IOMMU page mapping issues
       on x86 (XSA-378)(bsc#1189373).

  - CVE-2021-28697: grant table v2 status pages may remain accessible after
       de-allocation (XSA-379)(bsc#1189376).

  - CVE-2021-28698: long running loops in grant table handling
       (XSA-380)(bsc#1189378).

  - CVE-2021-28699: inadequate grant-v2 status frames array bounds check
       (XSA-382)(bsc#1189380).

  - CVE-2021-28700: No memory limit for dom0less domUs
       (XSA-383)(bsc#1189381).

     Other issues fixed:

  - Fixed 'Panic on CPU 0: IO-APIC + timer doesn&#x27 t work!' (bsc#1180491)

  - Fixed an issue with xencommons, where file format expecations by fillup
       did not align (bsc#1185682)

  - Fixed shell macro expansion in the spec file, so that ExecStart= in
       xendomains-wait-disks.service is created correctly (bsc#1183877)

  - Upstream bug fixes (bsc#1027519)

  - Fixed Xen SLES11SP4 guest hangs on cluster (bsc#1188050).

  - xl monitoring process exits during xl save -p-c keep the monitoring
       process running to cleanup the domU during shutdown (bsc#1176189).

  - Dom0 hangs when pinning CPUs for dom0 with HVM guest (bsc#1179246).

  - Prevent superpage allocation in the LAPIC and ACPI_INFO range
       (bsc#1189882).

     This update was imported from the SUSE:SLE-15-SP2:Update update project.");

  script_tag(name:"affected", value:"'xen' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.13.3_02~lp152.2.27.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.13.3_02~lp152.2.27.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.13.3_02~lp152.2.27.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.13.3_02~lp152.2.27.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.13.3_02~lp152.2.27.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.13.3_02~lp152.2.27.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-xendomains-wait-disk", rpm:"xen-tools-xendomains-wait-disk~4.13.3_02~lp152.2.27.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.13.3_02~lp152.2.27.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.13.3_02~lp152.2.27.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.13.3_02~lp152.2.27.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit-debuginfo", rpm:"xen-libs-32bit-debuginfo~4.13.3_02~lp152.2.27.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.13.3_02~lp152.2.27.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.13.3_02~lp152.2.27.1", rls:"openSUSELeap15.2"))) {
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
