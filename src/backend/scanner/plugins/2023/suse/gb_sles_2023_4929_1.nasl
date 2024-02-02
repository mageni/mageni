# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4929.1");
  script_cve_id("CVE-2023-6204", "CVE-2023-6205", "CVE-2023-6206", "CVE-2023-6207", "CVE-2023-6208", "CVE-2023-6209", "CVE-2023-6212", "CVE-2023-6856", "CVE-2023-6857", "CVE-2023-6858", "CVE-2023-6859", "CVE-2023-6860", "CVE-2023-6861", "CVE-2023-6862", "CVE-2023-6863", "CVE-2023-6864", "CVE-2023-6865", "CVE-2023-6867");
  script_tag(name:"creation_date", value:"2023-12-21 04:19:57 +0000 (Thu, 21 Dec 2023)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-22 10:59:57 +0000 (Fri, 22 Dec 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4929-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4929-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234929-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2023:4929-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:
Firefox Extended Support Release 115.6.0 ESR changelog-entry (bsc#1217974)
 * CVE-2023-6856: Heap-buffer-overflow affecting WebGL DrawElementsInstanced method with Mesa VM driver (bmo#1843782).
 * CVE-2023-6857: Symlinks may resolve to smaller than expected buffers (bmo#1796023).
 * CVE-2023-6858: Heap buffer overflow in nsTextFragment (bmo#1826791).
 * CVE-2023-6859: Use-after-free in PR_GetIdentitiesLayer (bmo#1840144).
 * CVE-2023-6860: Potential sandbox escape due to VideoBridge lack of texture validation (bmo#1854669).
 * CVE-2023-6861: Heap buffer overflow affected nsWindow::PickerOpen(void) in headless mode (bmo#1864118).
 * CVE-2023-6862: Use-after-free in nsDNSService (bsc#1868042).
 * CVE-2023-6863: Undefined behavior in ShutdownObserver() (bmo#1868901).
 * CVE-2023-6864: Memory safety bugs fixed in Firefox 121, Firefox ESR 115.6, and Thunderbird 115.6.
 * CVE-2023-6865: Potential exposure of uninitialized data in EncryptingOutputStream (bmo#1864123).
 * CVE-2023-6867: Clickjacking permission prompts using the popup transition (bmo#1863863).
Fixed: Various security fixes and other quality improvements MFSA 2023-50 (bsc#1217230)
 * CVE-2023-6204 (bmo#1841050)
 Out-of-bound memory access in WebGL2 blitFramebuffer
 * CVE-2023-6205 (bmo#1854076)
 Use-after-free in MessagePort::Entangled
 * CVE-2023-6206 (bmo#1857430)
 Clickjacking permission prompts using the fullscreen
 transition
 * CVE-2023-6207 (bmo#1861344)
 Use-after-free in ReadableByteStreamQueueEntry::Buffer
 * CVE-2023-6208 (bmo#1855345)
 Using Selection API would copy contents into X11 primary
 selection.
 * CVE-2023-6209 (bmo#1858570)
 Incorrect parsing of relative URLs starting with '///'
 * CVE-2023-6212 (bmo#1658432, bmo#1820983, bmo#1829252,
 bmo#1856072, bmo#1856091, bmo#1859030, bmo#1860943,
 bmo#1862782)
 Memory safety bugs fixed in Firefox 120, Firefox ESR 115.5,
 and Thunderbird 115.5");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE CaaS Platform 4.0, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~115.6.0~150000.150.119.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~115.6.0~150000.150.119.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~115.6.0~150000.150.119.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~115.6.0~150000.150.119.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~115.6.0~150000.150.119.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~115.6.0~150000.150.119.1", rls:"SLES15.0SP1"))) {
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
