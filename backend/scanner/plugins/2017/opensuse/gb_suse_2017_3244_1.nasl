###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_3244_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for chromium openSUSE-SU-2017:3244-1 (chromium)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851660");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-12-09 07:39:49 +0100 (Sat, 09 Dec 2017)");
  script_cve_id("CVE-2017-15408", "CVE-2017-15409", "CVE-2017-15410", "CVE-2017-15411",
                "CVE-2017-15412", "CVE-2017-15413", "CVE-2017-15415", "CVE-2017-15416",
                "CVE-2017-15417", "CVE-2017-15418", "CVE-2017-15419", "CVE-2017-15420",
                "CVE-2017-15422", "CVE-2017-15423", "CVE-2017-15424", "CVE-2017-15425",
                "CVE-2017-15426", "CVE-2017-15427");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for chromium openSUSE-SU-2017:3244-1 (chromium)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update to Chromium 63.0.3239.84 fixes the following security issues:

  - CVE-2017-15408: Heap buffer overflow in PDFium

  - CVE-2017-15409: Out of bounds write in Skia

  - CVE-2017-15410: Use after free in PDFium

  - CVE-2017-15411: Use after free in PDFium

  - CVE-2017-15412: Use after free in libXML

  - CVE-2017-15413: Type confusion in WebAssembly

  - CVE-2017-15415: Pointer information disclosure in IPC call

  - CVE-2017-15416: Out of bounds read in Blink

  - CVE-2017-15417: Cross origin information disclosure in Skia

  - CVE-2017-15418: Use of uninitialized value in Skia

  - CVE-2017-15419: Cross origin leak of redirect URL in Blink

  - CVE-2017-15420: URL spoofing in Omnibox

  - CVE-2017-15422: Integer overflow in ICU

  - CVE-2017-15423: Issue with SPAKE implementation in BoringSSL

  - CVE-2017-15424: URL Spoof in Omnibox

  - CVE-2017-15425: URL Spoof in Omnibox

  - CVE-2017-15426: URL Spoof in Omnibox

  - CVE-2017-15427: Insufficient blocking of JavaScript in Omnibox");
  script_tag(name:"affected", value:"chromium on openSUSE Leap 42.3, openSUSE Leap 42.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.2|openSUSELeap42\.3)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~63.0.3239.84~104.41.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~63.0.3239.84~104.41.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~63.0.3239.84~104.41.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~63.0.3239.84~104.41.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~63.0.3239.84~104.41.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~63.0.3239.84~127.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~63.0.3239.84~127.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~63.0.3239.84~127.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~63.0.3239.84~127.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~63.0.3239.84~127.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
