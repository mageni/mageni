###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_1430_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for Chromium openSUSE-SU-2016:1430-1 (Chromium)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851321");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-03 16:25:08 +0530 (Fri, 03 Jun 2016)");
  script_cve_id("CVE-2016-1672", "CVE-2016-1673", "CVE-2016-1674", "CVE-2016-1675",
                "CVE-2016-1676", "CVE-2016-1677", "CVE-2016-1678", "CVE-2016-1679",
                "CVE-2016-1680", "CVE-2016-1681", "CVE-2016-1682", "CVE-2016-1683",
                "CVE-2016-1684", "CVE-2016-1685", "CVE-2016-1686", "CVE-2016-1687",
                "CVE-2016-1688", "CVE-2016-1689", "CVE-2016-1690", "CVE-2016-1691",
                "CVE-2016-1692", "CVE-2016-1693", "CVE-2016-1694", "CVE-2016-1695");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for Chromium openSUSE-SU-2016:1430-1 (Chromium)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'Chromium'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Chromium was updated to 51.0.2704.63 to fix the following vulnerabilities
  (boo#981886):

  - CVE-2016-1672: Cross-origin bypass in extension bindings

  - CVE-2016-1673: Cross-origin bypass in Blink

  - CVE-2016-1674: Cross-origin bypass in extensions

  - CVE-2016-1675: Cross-origin bypass in Blink

  - CVE-2016-1676: Cross-origin bypass in extension bindings

  - CVE-2016-1677: Type confusion in V8

  - CVE-2016-1678: Heap overflow in V8

  - CVE-2016-1679: Heap use-after-free in V8 bindings

  - CVE-2016-1680: Heap use-after-free in Skia

  - CVE-2016-1681: Heap overflow in PDFium

  - CVE-2016-1682: CSP bypass for ServiceWorker

  - CVE-2016-1683: Out-of-bounds access in libxslt

  - CVE-2016-1684: Integer overflow in libxslt

  - CVE-2016-1685: Out-of-bounds read in PDFium

  - CVE-2016-1686: Out-of-bounds read in PDFium

  - CVE-2016-1687: Information leak in extensions

  - CVE-2016-1688: Out-of-bounds read in V8

  - CVE-2016-1689: Heap buffer overflow in media

  - CVE-2016-1690: Heap use-after-free in Autofill

  - CVE-2016-1691: Heap buffer-overflow in Skia

  - CVE-2016-1692: Limited cross-origin bypass in ServiceWorker

  - CVE-2016-1693: HTTP Download of Software Removal Tool

  - CVE-2016-1694: HPKP pins removed on cache clearance

  - CVE-2016-1695: Various fixes from internal audits, fuzzing and other
  initiatives");
  script_tag(name:"affected", value:"Chromium on openSUSE Leap 42.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.1")
{

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~51.0.2704.63~51.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~51.0.2704.63~51.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~51.0.2704.63~51.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~51.0.2704.63~51.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~51.0.2704.63~51.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-gnome", rpm:"chromium-desktop-gnome~51.0.2704.63~51.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-kde", rpm:"chromium-desktop-kde~51.0.2704.63~51.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo", rpm:"chromium-ffmpegsumo~51.0.2704.63~51.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo-debuginfo", rpm:"chromium-ffmpegsumo-debuginfo~51.0.2704.63~51.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
