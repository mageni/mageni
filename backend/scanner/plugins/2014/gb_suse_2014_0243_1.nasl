###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_0243_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for chromium openSUSE-SU-2014:0243-1 (chromium)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850570");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-02-20 15:10:56 +0530 (Thu, 20 Feb 2014)");
  script_cve_id("CVE-2013-6641", "CVE-2013-6643", "CVE-2013-6644", "CVE-2013-6645",
                "CVE-2013-6646", "CVE-2013-6649", "CVE-2013-6650");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("SuSE Update for chromium openSUSE-SU-2014:0243-1 (chromium)");
  script_tag(name:"affected", value:"chromium on openSUSE 13.1, openSUSE 12.3");
  script_tag(name:"insight", value:"Chromium was updated to version 32.0.1700.102: Stable
  channel update:

  - Security Fixes:

  * CVE-2013-6649: Use-after-free in SVG images

  * CVE-2013-6650: Memory corruption in V8

  * and 12 other fixes

  - Other:

  * Mouse Pointer disappears after exiting full-screen
  mode

  * Drag and drop files into Chromium may not work
  properly

  * Quicktime Plugin crashes in Chromium

  * Chromium becomes unresponsive

  * Trackpad users may not be able to scroll horizontally

  * Scrolling does not work in combo box

  * Chromium does not work with all CSS minifiers such
  as  whitespace around a media query's `and` keyword

  - Update to Chromium 32.0.1700.77 Stable channel update:

  - Security fixes:

  * CVE-2013-6646: Use-after-free in web workers

  * CVE-2013-6641: Use-after-free related to forms

  * CVE-2013-6643: Unprompted sync with an attacker's
  Google account

  * CVE-2013-6645: Use-after-free related to speech
  input  elements

  * CVE-2013-6644: Various fixes from internal audits,
  fuzzing  and other initiatives

  - Other:

  * Tab indicators for sound, webcam and casting

  * Automatically blocking malware files

  * Lots of under the hood changes for stability and
  performance

  - Remove patch chromium-fix-chromedriver-build.diff as
  that  chromedriver is fixed upstream

  - Updated ExcludeArch to exclude aarch64, ppc, ppc64 and
  ppc64le.  This is based on missing build requires
  (valgrind, v8, etc)");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE12\.3|openSUSE13\.1)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE12.3")
{

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~32.0.1700.102~1.25.2", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~32.0.1700.102~1.25.2", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~32.0.1700.102~1.25.2", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~32.0.1700.102~1.25.2", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~32.0.1700.102~1.25.2", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-gnome", rpm:"chromium-desktop-gnome~32.0.1700.102~1.25.2", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-kde", rpm:"chromium-desktop-kde~32.0.1700.102~1.25.2", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo", rpm:"chromium-ffmpegsumo~32.0.1700.102~1.25.2", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo-debuginfo", rpm:"chromium-ffmpegsumo-debuginfo~32.0.1700.102~1.25.2", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-suid-helper", rpm:"chromium-suid-helper~32.0.1700.102~1.25.2", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-suid-helper-debuginfo", rpm:"chromium-suid-helper-debuginfo~32.0.1700.102~1.25.2", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSE13.1")
{

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~32.0.1700.102~17.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~32.0.1700.102~17.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~32.0.1700.102~17.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~32.0.1700.102~17.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~32.0.1700.102~17.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-gnome", rpm:"chromium-desktop-gnome~32.0.1700.102~17.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-kde", rpm:"chromium-desktop-kde~32.0.1700.102~17.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo", rpm:"chromium-ffmpegsumo~32.0.1700.102~17.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo-debuginfo", rpm:"chromium-ffmpegsumo-debuginfo~32.0.1700.102~17.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-suid-helper", rpm:"chromium-suid-helper~32.0.1700.102~17.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-suid-helper-debuginfo", rpm:"chromium-suid-helper-debuginfo~32.0.1700.102~17.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
