###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_2296_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for Chromium openSUSE-SU-2016:2296-1 (Chromium)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851391");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-14 05:45:01 +0200 (Wed, 14 Sep 2016)");
  script_cve_id("CVE-2016-5147", "CVE-2016-5148", "CVE-2016-5149", "CVE-2016-5150",
                "CVE-2016-5151", "CVE-2016-5152", "CVE-2016-5153", "CVE-2016-5154",
                "CVE-2016-5155", "CVE-2016-5156", "CVE-2016-5157", "CVE-2016-5158",
                "CVE-2016-5159", "CVE-2016-5160", "CVE-2016-5161", "CVE-2016-5162",
                "CVE-2016-5163", "CVE-2016-5164", "CVE-2016-5165", "CVE-2016-5166");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for Chromium openSUSE-SU-2016:2296-1 (Chromium)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'Chromium'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Chromium was updated to 53.0.2785.101 to fix a number of security issues
  and bugs.

  The following vulnerabilities were fixed: (boo#996648)

  - CVE-2016-5147: Universal XSS in Blink.

  - CVE-2016-5148: Universal XSS in Blink.

  - CVE-2016-5149: Script injection in extensions.

  - CVE-2016-5150: Use after free in Blink.

  - CVE-2016-5151: Use after free in PDFium.

  - CVE-2016-5152: Heap overflow in PDFium.

  - CVE-2016-5153: Use after destruction in Blink.

  - CVE-2016-5154: Heap overflow in PDFium.

  - CVE-2016-5155: Address bar spoofing.

  - CVE-2016-5156: Use after free in event bindings.

  - CVE-2016-5157: Heap overflow in PDFium.

  - CVE-2016-5158: Heap overflow in PDFium.

  - CVE-2016-5159: Heap overflow in PDFium.

  - CVE-2016-5161: Type confusion in Blink.

  - CVE-2016-5162: Extensions web accessible resources bypass.

  - CVE-2016-5163: Address bar spoofing.

  - CVE-2016-5164: Universal XSS using DevTools.

  - CVE-2016-5165: Script injection in DevTools.

  - CVE-2016-5166: SMB Relay Attack via Save Page As.

  - CVE-2016-5160: Extensions web accessible resources bypass.

  The following upstream fixes are included:

  - SPDY crasher fixes

  - Disable NV12 DXGI video on AMD

  - Forward --password-store switch to os_crypt

  - Tell the kernel to discard USB requests when they time out.

  - disallow WKBackForwardListItem navigations for pushState pages

  - arc: bluetooth: Fix advertised uuid

  - fix conflicting PendingIntent for stop button and swipe away

  A number of tracked build system fixes are included. (boo#996032,
  boo#99606, boo#995932)

  The following tracked regression fix is included: - Re-enable widevine
  plugin (boo#998328)

  rpmlint and rpmlint-mini were updated to work around a memory exhaustion
  problem with this package on 32 bit (boo#969732).");
  script_tag(name:"affected", value:"Chromium on openSUSE 13.2");
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

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~53.0.2785.101~120.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~53.0.2785.101~120.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~53.0.2785.101~120.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~53.0.2785.101~120.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-gnome", rpm:"chromium-desktop-gnome~53.0.2785.101~120.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-kde", rpm:"chromium-desktop-kde~53.0.2785.101~120.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo", rpm:"chromium-ffmpegsumo~53.0.2785.101~120.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo-debuginfo", rpm:"chromium-ffmpegsumo-debuginfo~53.0.2785.101~120.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpmlint-mini", rpm:"rpmlint-mini~1.5~8.7.2", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpmlint-mini-debuginfo", rpm:"rpmlint-mini-debuginfo~1.5~8.7.2", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpmlint-mini-debugsource", rpm:"rpmlint-mini-debugsource~1.5~8.7.2", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpmlint", rpm:"pmlint~1.5~39.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
