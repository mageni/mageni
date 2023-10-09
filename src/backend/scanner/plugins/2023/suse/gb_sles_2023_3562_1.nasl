# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.3562.1");
  script_cve_id("CVE-2023-4051", "CVE-2023-4053", "CVE-2023-4574", "CVE-2023-4575", "CVE-2023-4576", "CVE-2023-4577", "CVE-2023-4578", "CVE-2023-4580", "CVE-2023-4581", "CVE-2023-4582", "CVE-2023-4583", "CVE-2023-4584", "CVE-2023-4585");
  script_tag(name:"creation_date", value:"2023-09-11 04:20:41 +0000 (Mon, 11 Sep 2023)");
  script_version("2023-09-18T05:06:12+0000");
  script_tag(name:"last_modification", value:"2023-09-18 05:06:12 +0000 (Mon, 18 Sep 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-14 03:45:00 +0000 (Thu, 14 Sep 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:3562-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3562-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20233562-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2023:3562-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:
Firefox was updated to Extended Support Release 115.2.0 ESR (MFSA 2023-36) (bsc#1214606).

CVE-2023-4574: Fixed memory corruption in IPC ColorPickerShownCallback (bmo#1846688)
CVE-2023-4575: Fixed memory corruption in IPC FilePickerShownCallback (bmo#1846689)
CVE-2023-4576: Fixed integer Overflow in RecordedSourceSurfaceCreation (bmo#1846694)
CVE-2023-4577: Fixed memory corruption in JIT UpdateRegExpStatics (bmo#1847397)
CVE-2023-4051: Fixed full screen notification obscured by file open dialog (bmo#1821884)
CVE-2023-4578: Fixed Out of Memory Exception in SpiderMonkey could have triggered an (bmo#1839007)
CVE-2023-4053: Fixed full screen notification obscured by external program (bmo#1839079)
CVE-2023-4580: Fixed push notifications saved to disk unencrypted (bmo#1843046)
CVE-2023-4581: Fixed XLL file extensions downloadable without warnings (bmo#1843758)
CVE-2023-4582: Fixed buffer Overflow in WebGL glGetProgramiv (bmo#1773874)
CVE-2023-4583: Fixed browsing Context potentially not cleared when closing Private Window (bmo#1842030)
CVE-2023-4584: Fixed memory safety bugs fixed in Firefox 117, Firefox ESR 102.15, Firefox ESR 115.2, Thunderbird 102.15, and Thunderbird 115.2 (bmo#1843968, bmo#1845205, bmo#1846080, bmo#1846526, bmo#1847529)
CVE-2023-4585: Fixed memory safety bugs fixed in Firefox 117, Firefox ESR 115.2, and Thunderbird 115.2(bmo#1751583, bmo#1833504, bmo#1841082, bmo#1847904, bmo#1848999).");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~115.2.0~150000.150.100.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~115.2.0~150000.150.100.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~115.2.0~150000.150.100.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~115.2.0~150000.150.100.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~115.2.0~150000.150.100.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~115.2.0~150000.150.100.1", rls:"SLES15.0SP1"))) {
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
