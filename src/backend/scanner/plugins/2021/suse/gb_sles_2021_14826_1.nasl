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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.14826.1");
  script_cve_id("CVE-2021-29980", "CVE-2021-29981", "CVE-2021-29982", "CVE-2021-29983", "CVE-2021-29984", "CVE-2021-29985", "CVE-2021-29986", "CVE-2021-29987", "CVE-2021-29988", "CVE-2021-29989", "CVE-2021-29990", "CVE-2021-29991", "CVE-2021-32810", "CVE-2021-38492", "CVE-2021-38495", "CVE-2021-38496", "CVE-2021-38497", "CVE-2021-38498", "CVE-2021-38500", "CVE-2021-38501");
  script_tag(name:"creation_date", value:"2021-10-19 02:19:26 +0000 (Tue, 19 Oct 2021)");
  script_version("2021-10-19T02:19:26+0000");
  script_tag(name:"last_modification", value:"2021-10-19 10:35:24 +0000 (Tue, 19 Oct 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-11 17:52:00 +0000 (Wed, 11 Aug 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:14826-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:14826-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-202114826-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, rust-cbindgen' package(s) announced via the SUSE-SU-2021:14826-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox, rust-cbindgen fixes the following issues:

MozillaFirefox was updated to Extended Support Release 91.2.0 ESR

Fixed: Various stability, functionality, and security fixes

MFSA 2021-45 (bsc#1191332)

 * CVE-2021-38496: Use-after-free in MessageTask
 * CVE-2021-38497: Validation message could have been overlaid on another
 origin
 * CVE-2021-38498: Use-after-free of nsLanguageAtomService object
 * CVE-2021-32810: Data race in crossbeam-deque
 * CVE-2021-38500: Memory safety bugs fixed in Firefox 93, Firefox ESR
 78.15, and Firefox ESR 91.2
 * CVE-2021-38501: Memory safety bugs fixed in Firefox 93 and Firefox ESR
 91.2

Fixed crash in FIPS mode (bsc#1190710)

Firefox Extended Support Release 91.1.0 ESR

Fixed: Various stability, functionality, and security fixes

MFSA 2021-40 (bsc#1190269, bsc#1190274)

CVE-2021-38492: Navigating to `mk:` URL scheme could load Internet
 Explorer

CVE-2021-38495: Memory safety bugs fixed in Firefox 92 and Firefox ESR
 91.1

Firefox 91.0.1esr ESR

 * Fixed: Fixed an issue causing buttons on the tab bar to be resized
 when loading certain websites (bug 1704404) (bmo#1704404)
 * Fixed: Fixed an issue which caused tabs from private windows to be
 visible in non-private windows when viewing switch-to- tab results in
 the address bar panel (bug 1720369) (bmo#1720369)
 * Fixed: Various stability fixes
 * Fixed: Security fix MFSA 2021-37 (bsc#1189547)
 * CVE-2021-29991 (bmo#1724896) Header Splitting possible with HTTP/3
 Responses

Firefox Extended Support Release 91.0 ESR

 * New: Some of the highlights of the new Extended Support Release are:
 - A number of user interface changes. For more information, see the
 Firefox 89 release notes.
 - Firefox now supports logging into Microsoft, work, and school
 accounts using Windows single sign-on. Learn more
 - On Windows, updates can now be applied in the background while
 Firefox is not running.
 - Firefox for Windows now offers a new page about:third-party to help
 identify compatibility issues caused by third-party applications
 - Version 2 of Firefox's SmartBlock feature further improves private
 browsing. Third party Facebook scripts are blocked to prevent you
 from being tracked, but are now automatically loaded 'just in time'
 if you decide to 'Log in with Facebook'
 on any website.
 - Enhanced the privacy of the Firefox Browser's Private Browsing mode
 with Total Cookie Protection, which confines cookies to the site
 where they were created, preventing companis from using cookies to
 track your browsing across sites. This feature was originally
 launched in Firefox's ETP Strict mode.
 - PDF forms now support JavaScript embedded in PDF files. Some PDF
 forms use JavaScript for validation and other interactive features.
 - You'll encounter less website breakage in Private Browsing and
 Strict Enhanced Tracking Protection with SmartBlock, which provides
 stand-in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'MozillaFirefox, rust-cbindgen' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~91.2.0~78.143.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~91~21.18.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~91.2.0~78.143.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~91.2.0~78.143.1", rls:"SLES11.0SP4"))) {
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
