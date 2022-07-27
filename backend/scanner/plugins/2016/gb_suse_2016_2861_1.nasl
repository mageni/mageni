###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_2861_1.nasl 12637 2018-12-04 08:36:44Z mmartin $
#
# SuSE Update for MozillaFirefox, mozilla-nss openSUSE-SU-2016:2861-1 (MozillaFirefox, mozilla-nss)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851435");
  script_version("$Revision: 12637 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 09:36:44 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2016-11-19 05:37:18 +0100 (Sat, 19 Nov 2016)");
  script_cve_id("CVE-2016-5289", "CVE-2016-5290", "CVE-2016-5291", "CVE-2016-5292",
                "CVE-2016-5296", "CVE-2016-5297", "CVE-2016-9063", "CVE-2016-9064",
                "CVE-2016-9066", "CVE-2016-9067", "CVE-2016-9068", "CVE-2016-9069",
                "CVE-2016-9070", "CVE-2016-9071", "CVE-2016-9073", "CVE-2016-9074",
                "CVE-2016-9075", "CVE-2016-9076", "CVE-2016-9077");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for MozillaFirefox, mozilla-nss openSUSE-SU-2016:2861-1 (MozillaFirefox, mozilla-nss)");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update to Mozilla Firefox 50.0 fixes a number of security issues.

  The following vulnerabilities were fixed in Mozilla Firefox (MFSA 2016-89):

  - CVE-2016-5296: Heap-buffer-overflow WRITE in rasterize_edges_1
  (bmo#1292443)

  - CVE-2016-5292: URL parsing causes crash (bmo#1288482)

  - CVE-2016-5297: Incorrect argument length checking in Javascript
  (bmo#1303678)

  - CVE-2016-9064: Addons update must verify IDs match between current and
  new versions (bmo#1303418)

  - CVE-2016-9066: Integer overflow leading to a buffer overflow in
  nsScriptLoadHandler (bmo#1299686)

  - CVE-2016-9067: heap-use-after-free in nsINode::ReplaceOrInsertBefore
  (bmo#1301777, bmo#1308922 (CVE-2016-9069))

  - CVE-2016-9068: heap-use-after-free in nsRefreshDriver (bmo#1302973)

  - CVE-2016-9075: WebExtensions can access the mozAddonManager API and use
  it to gain elevated privileges (bmo#1295324)

  - CVE-2016-9077: Canvas filters allow feDisplacementMaps to be applied to
  cross-origin images, allowing timing attacks on them (bmo#1298552)

  - CVE-2016-5291: Same-origin policy violation using local HTML file and
  saved shortcut file (bmo#1292159)

  - CVE-2016-9070: Sidebar bookmark can have reference to chrome window
  (bmo#1281071)

  - CVE-2016-9073: windows.create schema doesn't specify 'format':
  'relativeUrl' (bmo#1289273)

  - CVE-2016-9076: select dropdown menu can be used for URL bar spoofing on
  e10s (bmo#1276976)

  - CVE-2016-9063: Possible integer overflow to fix inside XML_Parse in
  expat (bmo#1274777)

  - CVE-2016-9071: Probe browser history via HSTS/301 redirect + CSP
  (bmo#1285003)

  - CVE-2016-5289: Memory safety bugs fixed in Firefox 50

  - CVE-2016-5290: Memory safety bugs fixed in Firefox 50 and Firefox ESR
  45.5

  The following vulnerabilities were fixed in Mozilla NSS 3.26.1:

  - CVE-2016-9074: Insufficient timing side-channel resistance in divSpoiler
  (bmo#1293334)

  Mozilla Firefox now requires mozilla-nss 3.26.2.

  New features in Mozilla Firefox:

  - Updates to keyboard shortcuts Set a preference to have Ctrl+Tab cycle
  through tabs in recently used order View a page in Reader Mode by using
  Ctrl+Alt+R

  - Added option to Find in page that allows users to limit search to whole
  words only

  - Added download protection for a large number of executable file types on
  Windows, Mac and Linux

  - Fixed rendering of dashed and dotted borders with rounded corners
  (border-radius)

  - Added a built-in Emoji set for operating systems without native Emoji
  fonts

  - Blocked versions of libavcodec older than 54.35.1

  - additional locale

  mozi ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"MozillaFirefox, mozilla-nss on openSUSE Leap 42.1, openSUSE 13.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, mozilla-nss'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~50.0~88.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~50.0~88.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~50.0~88.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~50.0~88.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~50.0~88.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~50.0~88.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~50.0~88.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~50.0~88.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3-debuginfo", rpm:"libfreebl3-debuginfo~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3-debuginfo", rpm:"libsoftokn3-debuginfo~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo", rpm:"mozilla-nss-certs-debuginfo~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-debuginfo", rpm:"mozilla-nss-debuginfo~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-debugsource", rpm:"mozilla-nss-debugsource~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo", rpm:"mozilla-nss-sysinit-debuginfo~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-tools-debuginfo", rpm:"mozilla-nss-tools-debuginfo~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3-debuginfo-32bit", rpm:"libfreebl3-debuginfo-32bit~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3-debuginfo-32bit", rpm:"libsoftokn3-debuginfo-32bit~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo-32bit", rpm:"mozilla-nss-certs-debuginfo-32bit~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-debuginfo-32bit", rpm:"mozilla-nss-debuginfo-32bit~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit-32bit", rpm:"mozilla-nss-sysinit-32bit~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo-32bit", rpm:"mozilla-nss-sysinit-debuginfo-32bit~3.26.2~49.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
