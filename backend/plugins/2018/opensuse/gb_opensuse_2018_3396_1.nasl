###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for Chromium openSUSE-SU-2018:3396-1 (Chromium)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851948");
  script_version("2019-05-03T10:20:18+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:20:18 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-10-25 06:00:36 +0200 (Thu, 25 Oct 2018)");
  script_cve_id("CVE-2018-17462", "CVE-2018-17463", "CVE-2018-17464", "CVE-2018-17465", "CVE-2018-17466", "CVE-2018-17467", "CVE-2018-17468", "CVE-2018-17469", "CVE-2018-17470", "CVE-2018-17471", "CVE-2018-17472", "CVE-2018-17473", "CVE-2018-17474", "CVE-2018-17475", "CVE-2018-17476", "CVE-2018-17477", "CVE-2018-5179");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for Chromium openSUSE-SU-2018:3396-1 (Chromium)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'Chromium'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for Chromium to version 70.0.3538.67 fixes multiple issues.

  Security issues fixed (bsc#1112111):

  - CVE-2018-17462: Sandbox escape in AppCache

  - CVE-2018-17463: Remote code execution in V8

  - Heap buffer overflow in Little CMS in PDFium

  - CVE-2018-17464: URL spoof in Omnibox

  - CVE-2018-17465: Use after free in V8

  - CVE-2018-17466: Memory corruption in Angle

  - CVE-2018-17467: URL spoof in Omnibox

  - CVE-2018-17468: Cross-origin URL disclosure in Blink

  - CVE-2018-17469: Heap buffer overflow in PDFium

  - CVE-2018-17470: Memory corruption in GPU Internals

  - CVE-2018-17471: Security UI occlusion in full screen mode

  - CVE-2018-17473: URL spoof in Omnibox

  - CVE-2018-17474: Use after free in Blink

  - CVE-2018-17475: URL spoof in Omnibox

  - CVE-2018-17476: Security UI occlusion in full screen mode

  - CVE-2018-5179: Lack of limits on update() in ServiceWorker

  - CVE-2018-17477: UI spoof in Extensions

  VAAPI hardware accelerated rendering is now enabled by default.

  This update contains the following packaging changes:

  - Use the system libusb-1.0 library

  - Use bundled harfbuzz library

  - Disable gnome-keyring to avoid crashes


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1253=1");
  script_tag(name:"affected", value:"Chromium on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-10/msg00062.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~70.0.3538.67~179.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~70.0.3538.67~179.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~70.0.3538.67~179.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~70.0.3538.67~179.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~70.0.3538.67~179.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
