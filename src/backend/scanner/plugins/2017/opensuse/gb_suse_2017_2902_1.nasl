###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_2902_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for chromium openSUSE-SU-2017:2902-1 (chromium)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851634");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-10-30 09:23:49 +0100 (Mon, 30 Oct 2017)");
  script_cve_id("CVE-2017-15386", "CVE-2017-15387", "CVE-2017-15388", "CVE-2017-15389",
                "CVE-2017-15390", "CVE-2017-15391", "CVE-2017-15392", "CVE-2017-15393",
                "CVE-2017-15394", "CVE-2017-15395", "CVE-2017-15396", "CVE-2017-5124",
                "CVE-2017-5125", "CVE-2017-5126", "CVE-2017-5127", "CVE-2017-5128",
                "CVE-2017-5129", "CVE-2017-5130", "CVE-2017-5131", "CVE-2017-5132",
                "CVE-2017-5133");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for chromium openSUSE-SU-2017:2902-1 (chromium)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update to Chromium 62.0.3202.75 fixes the following security issues:

  - CVE-2017-5124: UXSS with MHTML

  - CVE-2017-5125: Heap overflow in Skia

  - CVE-2017-5126: Use after free in PDFium

  - CVE-2017-5127: Use after free in PDFium

  - CVE-2017-5128: Heap overflow in WebGL

  - CVE-2017-5129: Use after free in WebAudio

  - CVE-2017-5132: Incorrect stack manipulation in WebAssembly.

  - CVE-2017-5130: Heap overflow in libxml2

  - CVE-2017-5131: Out of bounds write in Skia

  - CVE-2017-5133: Out of bounds write in Skia

  - CVE-2017-15386: UI spoofing in Blink

  - CVE-2017-15387: Content security bypass

  - CVE-2017-15388: Out of bounds read in Skia

  - CVE-2017-15389: URL spoofing in OmniBox

  - CVE-2017-15390: URL spoofing in OmniBox

  - CVE-2017-15391: Extension limitation bypass in Extensions.

  - CVE-2017-15392: Incorrect registry key handling in PlatformIntegration

  - CVE-2017-15393: Referrer leak in Devtools

  - CVE-2017-15394: URL spoofing in extensions UI

  - CVE-2017-15395: Null pointer dereference in ImageCapture

  - CVE-2017-15396: Stack overflow in V8");
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

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~62.0.3202.75~104.32.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~62.0.3202.75~104.32.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~62.0.3202.75~104.32.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~62.0.3202.75~104.32.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~62.0.3202.75~104.32.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~62.0.3202.75~118.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~62.0.3202.75~118.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~62.0.3202.75~118.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~62.0.3202.75~118.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~62.0.3202.75~118.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
