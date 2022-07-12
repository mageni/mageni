###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0441_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for chromium openSUSE-SU-2015:0441-1 (chromium)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850639");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-03-06 14:17:10 +0100 (Fri, 06 Mar 2015)");
  script_cve_id("CVE-2014-7923", "CVE-2014-7924", "CVE-2014-7925", "CVE-2014-7926", "CVE-2014-7927", "CVE-2014-7928", "CVE-2014-7929", "CVE-2014-7930", "CVE-2014-7931", "CVE-2014-7932", "CVE-2014-7933", "CVE-2014-7934", "CVE-2014-7935", "CVE-2014-7936", "CVE-2014-7937", "CVE-2014-7938", "CVE-2014-7939", "CVE-2014-7940", "CVE-2014-7941", "CVE-2014-7942", "CVE-2014-7943", "CVE-2014-7944", "CVE-2014-7945", "CVE-2014-7946", "CVE-2014-7947", "CVE-2014-7948", "CVE-2015-1205", "CVE-2015-1209", "CVE-2015-1210", "CVE-2015-1211", "CVE-2015-1212");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for chromium openSUSE-SU-2015:0441-1 (chromium)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"chromium was updated to version 40.0.2214.111 to fix 31 vulnerabilities.

  These security issues were fixed:

  - CVE-2015-1209: Use-after-free in DOM (bnc#916841).

  - CVE-2015-1210: Cross-origin-bypass in V8 bindings (bnc#916843).

  - CVE-2015-1211: Privilege escalation using service workers (bnc#916838).

  - CVE-2015-1212: Various fixes from internal audits, fuzzing and other
  initiatives (bnc#916840).

  - CVE-2014-7923: Memory corruption in ICU (bnc#914468).

  - CVE-2014-7924: Use-after-free in IndexedDB (bnc#914468).

  - CVE-2014-7925: Use-after-free in WebAudio (bnc#914468).

  - CVE-2014-7926: Memory corruption in ICU (bnc#914468).

  - CVE-2014-7927: Memory corruption in V8 (bnc#914468).

  - CVE-2014-7928: Memory corruption in V8 (bnc#914468).

  - CVE-2014-7930: Use-after-free in DOM (bnc#914468).

  - CVE-2014-7931: Memory corruption in V8 (bnc#914468).

  - CVE-2014-7929: Use-after-free in DOM (bnc#914468).

  - CVE-2014-7932: Use-after-free in DOM (bnc#914468).

  - CVE-2014-7933: Use-after-free in FFmpeg (bnc#914468).

  - CVE-2014-7934: Use-after-free in DOM (bnc#914468).

  - CVE-2014-7935: Use-after-free in Speech (bnc#914468).

  - CVE-2014-7936: Use-after-free in Views (bnc#914468).

  - CVE-2014-7937: Use-after-free in FFmpeg (bnc#914468).

  - CVE-2014-7938: Memory corruption in Fonts (bnc#914468).

  - CVE-2014-7939: Same-origin-bypass in V8 (bnc#914468).

  - CVE-2014-7940: Uninitialized-value in ICU (bnc#914468).

  - CVE-2014-7941: Out-of-bounds read in UI (bnc#914468).

  - CVE-2014-7942: Uninitialized-value in Fonts (bnc#914468).

  - CVE-2014-7943: Out-of-bounds read in Skia

  - CVE-2014-7944: Out-of-bounds read in PDFium

  - CVE-2014-7945: Out-of-bounds read in PDFium

  - CVE-2014-7946: Out-of-bounds read in Fonts

  - CVE-2014-7947: Out-of-bounds read in PDFium

  - CVE-2014-7948: Caching error in AppCache

  - CVE-2015-1205: Various fixes from internal audits, fuzzing and other
  initiatives

  These non-security issues were fixed:

  - Fix using 'echo' command in chromium-browser.sh script");
  script_tag(name:"affected", value:"chromium on openSUSE 13.1");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.1")
{

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~40.0.2214.111~68.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~40.0.2214.111~68.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~40.0.2214.111~68.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~40.0.2214.111~68.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~40.0.2214.111~68.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-gnome", rpm:"chromium-desktop-gnome~40.0.2214.111~68.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-kde", rpm:"chromium-desktop-kde~40.0.2214.111~68.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo", rpm:"chromium-ffmpegsumo~40.0.2214.111~68.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo-debuginfo", rpm:"chromium-ffmpegsumo-debuginfo~40.0.2214.111~68.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}