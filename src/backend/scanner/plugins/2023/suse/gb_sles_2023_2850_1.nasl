# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2850.1");
  script_cve_id("CVE-2023-3482", "CVE-2023-37201", "CVE-2023-37202", "CVE-2023-37203", "CVE-2023-37204", "CVE-2023-37205", "CVE-2023-37206", "CVE-2023-37207", "CVE-2023-37208", "CVE-2023-37209", "CVE-2023-37210", "CVE-2023-37211", "CVE-2023-37212");
  script_tag(name:"creation_date", value:"2023-07-17 11:37:31 +0000 (Mon, 17 Jul 2023)");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-11 14:28:00 +0000 (Tue, 11 Jul 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2850-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2850-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232850-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, MozillaFirefox-branding-SLE' package(s) announced via the SUSE-SU-2023:2850-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox, MozillaFirefox-branding-SLE fixes the following issues:
Changes in MozillaFirefox and MozillaFirefox-branding-SLE:
This update provides Firefox Extended Support Release 115.0 ESR


New:


Required fields are now highlighted in PDF forms.

Improved performance on high-refresh rate monitors (120Hz+).
Buttons in the Tabs toolbar can now be reached with Tab,
 Shift+Tab, and Arrow keys. View this article for additional
 details.
Windows' 'Make text bigger' accessibility setting now
 affects all the UI and content pages, rather than only
 applying to system font sizes.
Non-breaking spaces are now preserved--preventing automatic
 line breaks--when copying text from a form control.
Fixed WebGL performance issues on NVIDIA binary drivers via
 DMA-Buf on Linux.
Fixed an issue in which Firefox startup could be
 significantly slowed down by the processing of Web content
 local storage. This had the greatest impact on users with
 platter hard drives and significant local storage.
Removed a configuration option to allow SHA-1 signatures in
 certificates: SHA-1 signatures in certificates--long since
 determined to no longer be secure enough--are now not
 supported.
Highlight color is preserved correctly after typing Enter
 in the mail composer of Yahoo Mail and Outlook.
 After bypassing the https only error page navigating back
 would take you to the error page that was previously
 dismissed. Back now takes you to the previous site that was
 visited.
Paste unformatted shortcut (shift+ctrl/cmd+v) now works in
 plain text contexts, such as input and text area.
Added an option to print only the current page from the
 print preview dialog.
Swipe to navigate (two fingers on a touchpad swiped left or
 right to perform history back or forward) on Windows is now
 enabled.
Stability on Windows is significantly improved as Firefox
 handles low-memory situations much better.
Touchpad scrolling on macOS was made more accessible by
 reducing unintended diagonal scrolling opposite of the
 intended scroll axis.
Firefox is less likely to run out of memory on Linux and
 performs more efficiently for the rest of the system when
 memory runs low.
It is now possible to edit PDFs: including writing text,
 drawing, and adding signatures.
Setting Firefox as your default browser now also makes it
 the default PDF application on Windows systems.
Swipe-to-navigate (two fingers on a touchpad swiped left or
 right to perform history back or forward) now works for Linux
 users on Wayland.
Text Recognition in images allows users on macOS 10.15 and
 higher to extract text from the selected image (such as a
 meme or screenshot).
Firefox View helps you get back to content you previously
 discovered. A pinned tab allows you to find and open recently
 closed tabs on your current device and access tabs from other
 devices (via our 'Tab Pickup' feature).
Import maps, which allow web pages ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'MozillaFirefox, MozillaFirefox-branding-SLE' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~115.0~112.165.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLE", rpm:"MozillaFirefox-branding-SLE~115~35.12.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~115.0~112.165.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~115.0~112.165.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~115.0~112.165.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~115.0~112.165.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~115.0~112.165.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLE", rpm:"MozillaFirefox-branding-SLE~115~35.12.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~115.0~112.165.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~115.0~112.165.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~115.0~112.165.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~115.0~112.165.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~115.0~112.165.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLE", rpm:"MozillaFirefox-branding-SLE~115~35.12.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~115.0~112.165.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~115.0~112.165.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~115.0~112.165.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~115.0~112.165.1", rls:"SLES12.0SP5"))) {
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
