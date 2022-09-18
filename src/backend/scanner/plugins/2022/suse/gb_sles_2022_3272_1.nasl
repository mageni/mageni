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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3272.1");
  script_cve_id("CVE-2022-2200", "CVE-2022-2505", "CVE-2022-34468", "CVE-2022-34469", "CVE-2022-34470", "CVE-2022-34471", "CVE-2022-34472", "CVE-2022-34473", "CVE-2022-34474", "CVE-2022-34475", "CVE-2022-34476", "CVE-2022-34477", "CVE-2022-34478", "CVE-2022-34479", "CVE-2022-34480", "CVE-2022-34481", "CVE-2022-34482", "CVE-2022-34483", "CVE-2022-34484", "CVE-2022-34485", "CVE-2022-36314", "CVE-2022-36318", "CVE-2022-36319", "CVE-2022-38472", "CVE-2022-38473", "CVE-2022-38476", "CVE-2022-38477", "CVE-2022-38478");
  script_tag(name:"creation_date", value:"2022-09-15 04:54:24 +0000 (Thu, 15 Sep 2022)");
  script_version("2022-09-15T10:11:06+0000");
  script_tag(name:"last_modification", value:"2022-09-15 10:11:06 +0000 (Thu, 15 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3272-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3272-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223272-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2022:3272-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

Mozilla Firefox was updated to 102.2.0esr ESR:

Fixed: Various stability, functionality, and security fixes.

MFSA 2022-34 (bsc#1202645)

 * CVE-2022-38472 (bmo#1769155) Address bar spoofing via XSLT error
 handling
 * CVE-2022-38473 (bmo#1771685) Cross-origin XSLT Documents would have
 inherited the parent's permissions
 * CVE-2022-38476 (bmo#1760998) Data race and potential use-after-free in
 PK11_ChangePW
 * CVE-2022-38477 (bmo#1760611, bmo#1770219, bmo#1771159, bmo#1773363)
 Memory safety bugs fixed in Firefox 104 and Firefox ESR 102.2
 * CVE-2022-38478 (bmo#1770630, bmo#1776658) Memory safety bugs fixed in
 Firefox 104, Firefox ESR 102.2, and Firefox ESR 91.13

Firefox Extended Support Release 102.1 ESR

 * Fixed: Various stability, functionality, and security fixes.

MFSA 2022-30 (bsc#1201758)

 * CVE-2022-36319 (bmo#1737722) Mouse Position spoofing with CSS
 transforms
 * CVE-2022-36318 (bmo#1771774) Directory indexes for bundled resources
 reflected URL parameters
 * CVE-2022-36314 (bmo#1773894) Opening local .lnk files
 could cause unexpected network loads
 * CVE-2022-2505 (bmo#1769739, bmo#1772824) Memory safety bugs fixed in
 Firefox 103 and 102.1

Firefox Extended Support Release 102.0.1 ESR

 * Fixed: Fixed bookmark shortcut creation by dragging to Windows File
 Explorer and dropping partially broken (bmo#1774683)
 * Fixed: Fixed bookmarks sidebar flashing white when opened in dark mode
 (bmo#1776157)
 * Fixed: Fixed multilingual spell checking not working with content in
 both English and a non-Latin alphabet (bmo#1773802)
 * Fixed: Developer tools: Fixed an issue where the console
 output keep getting scrolled to the bottom when the last visible
 message is an evaluation result (bmo#1776262)
 * Fixed: Fixed *Delete cookies and site data when Firefox is closed*
 checkbox getting disabled on startup (bmo#1777419)
 * Fixed: Various stability fixes

Firefox 102.0 ESR:

New:

 - We now provide more secure connections: Firefox can now automatically
 upgrade to HTTPS using HTTPS RR as Alt-Svc headers.
 - For added viewing pleasure, full-range color levels are now supported
 for video playback on many systems.
 - Find it easier now! Mac users can now access the macOS share options
 from the Firefox File menu.
 - Voila! Support for images containing ICC v4 profiles is enabled on
 macOS.
 - Firefox now supports the new AVIF image format, which is based on the
 modern and royalty-free AV1 video codec. It
 offers significant bandwidth savings for sites compared to existing
 image formats. It also supports transparency and
 other advanced features.
 - Firefox PDF viewer now supports filling more forms (e.g., XFA-based
 forms, used by multiple governments and banks). Learn more.
 - When available system memory is critically low, Firefox on Windows
 will automatically unload tabs based on their last access time, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~102.2.0~150000.150.56.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLE", rpm:"MozillaFirefox-branding-SLE~102~150000.4.22.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~102.2.0~150000.150.56.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~102.2.0~150000.150.56.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~102.2.0~150000.150.56.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~102.2.0~150000.150.56.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~102.2.0~150000.150.56.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~102.2.0~150000.150.56.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLE", rpm:"MozillaFirefox-branding-SLE~102~150000.4.22.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~102.2.0~150000.150.56.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~102.2.0~150000.150.56.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~102.2.0~150000.150.56.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~102.2.0~150000.150.56.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~102.2.0~150000.150.56.1", rls:"SLES15.0SP1"))) {
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
