###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_2368_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for MozillaFirefox, mozilla-nss openSUSE-SU-2016:2368-1 (MozillaFirefox, mozilla-nss)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851395");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-25 05:45:03 +0200 (Sun, 25 Sep 2016)");
  script_cve_id("CVE-2016-2827", "CVE-2016-5256", "CVE-2016-5257", "CVE-2016-5270",
                "CVE-2016-5271", "CVE-2016-5272", "CVE-2016-5273", "CVE-2016-5274",
                "CVE-2016-5275", "CVE-2016-5276", "CVE-2016-5277", "CVE-2016-5278",
                "CVE-2016-5279", "CVE-2016-5280", "CVE-2016-5281", "CVE-2016-5282",
                "CVE-2016-5283", "CVE-2016-5284");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for MozillaFirefox, mozilla-nss openSUSE-SU-2016:2368-1 (MozillaFirefox, mozilla-nss)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, mozilla-nss'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for MozillaFirefox and mozilla-nss fixes the following issues:

  MozillaFirefox was updated to version 49.0 (boo#999701)

  - New features

  * Updated Firefox Login Manager to allow HTTPS pages to use saved HTTP
  logins.

  * Added features to Reader Mode that make it easier on the eyes and the
  ears

  * Improved video performance for users on systems that support SSE3
  without hardware acceleration

  * Added context menu controls to HTML5 audio and video that let users
  loops files or play files at 1.25x speed

  * Improvements in about:memory reports for tracking font memory usage

  - Security related fixes

  * MFSA 2016-85 CVE-2016-2827 (bmo#1289085) - Out-of-bounds read in
  mozilla::net::IsValidReferrerPolicy CVE-2016-5270 (bmo#1291016) -
  Heap-buffer-overflow in nsCaseTransformTextRunFactory::TransformString
  CVE-2016-5271 (bmo#1288946) - Out-of-bounds read in
  PropertyProvider::GetSpacingInternal CVE-2016-5272 (bmo#1297934) - Bad
  cast in nsImageGeometryMixin CVE-2016-5273 (bmo#1280387) - crash in
  mozilla::a11y::HyperTextAccessible::GetChildOffset CVE-2016-5276
  (bmo#1287721) - Heap-use-after-free in
  mozilla::a11y::DocAccessible::ProcessInvalidationList CVE-2016-5274
  (bmo#1282076) - use-after-free in nsFrameManager::CaptureFrameState
  CVE-2016-5277 (bmo#1291665) - Heap-use-after-free in
  nsRefreshDriver::Tick CVE-2016-5275 (bmo#1287316) -
  global-buffer-overflow in
  mozilla::gfx::FilterSupport::ComputeSourceNeededRegions CVE-2016-5278
  (bmo#1294677) - Heap-buffer-overflow in nsBMPEncoder::AddImageFrame
  CVE-2016-5279 (bmo#1249522) - Full local path of files is available to
  web pages after drag and drop CVE-2016-5280 (bmo#1289970) -
  Use-after-free in
  mozilla::nsTextNodeDirectionalityMap::RemoveElementFromMap
  CVE-2016-5281 (bmo#1284690) - use-after-free in DOMSVGLength
  CVE-2016-5282 (bmo#932335) - Don't allow content to request favicons
  from non-whitelisted schemes CVE-2016-5283 (bmo#928187) -  iframe src
  fragment timing attack can reveal cross-origin data CVE-2016-5284
  (bmo#1303127) - Add-on update site certificate pin expiration
  CVE-2016-5256 - Memory safety bugs fixed in Firefox 49 CVE-2016-5257 -
  Memory safety bugs fixed in Firefox 49 and Firefox ESR 45.4

  - requires NSS 3.25

  - Mozilla Firefox 48.0.2:

  * Mitigate a startup crash issue caused on Windows (bmo#1291738)

  mozilla-nss was updated to NSS 3.25. New functionality:

  * Implemented DHE key agreement for TLS 1.3

  * Added support for ChaCha with TLS 1.3

  * Added support for TLS 1.2 ciphersuites that use SHA384 as the PRF

  * In previous v ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"MozillaFirefox, mozilla-nss on openSUSE Leap 42.1, openSUSE 13.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
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

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~49.0~80.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~49.0~80.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~49.0~80.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~49.0~80.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~49.0~80.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~49.0~80.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~49.0~80.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~49.0~80.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3-debuginfo", rpm:"libfreebl3-debuginfo~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3-debuginfo", rpm:"libsoftokn3-debuginfo~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo", rpm:"mozilla-nss-certs-debuginfo~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-debuginfo", rpm:"mozilla-nss-debuginfo~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-debugsource", rpm:"mozilla-nss-debugsource~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo", rpm:"mozilla-nss-sysinit-debuginfo~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-tools-debuginfo", rpm:"mozilla-nss-tools-debuginfo~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3-debuginfo-32bit", rpm:"libfreebl3-debuginfo-32bit~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3-debuginfo-32bit", rpm:"libsoftokn3-debuginfo-32bit~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo-32bit", rpm:"mozilla-nss-certs-debuginfo-32bit~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-debuginfo-32bit", rpm:"mozilla-nss-debuginfo-32bit~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit-32bit", rpm:"mozilla-nss-sysinit-32bit~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo-32bit", rpm:"mozilla-nss-sysinit-debuginfo-32bit~3.25~46.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
