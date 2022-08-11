###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2134_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for Chromium openSUSE-SU-2018:2134-1 (Chromium)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851823");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-07-29 05:58:00 +0200 (Sun, 29 Jul 2018)");
  script_cve_id("CVE-2018-4117", "CVE-2018-6044", "CVE-2018-6153", "CVE-2018-6154", "CVE-2018-6155", "CVE-2018-6156", "CVE-2018-6157", "CVE-2018-6158", "CVE-2018-6159", "CVE-2018-6161", "CVE-2018-6162", "CVE-2018-6163", "CVE-2018-6164", "CVE-2018-6165", "CVE-2018-6166", "CVE-2018-6167", "CVE-2018-6168", "CVE-2018-6169", "CVE-2018-6170", "CVE-2018-6171", "CVE-2018-6172", "CVE-2018-6173", "CVE-2018-6174", "CVE-2018-6175", "CVE-2018-6176", "CVE-2018-6177", "CVE-2018-6178", "CVE-2018-6179");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for Chromium openSUSE-SU-2018:2134-1 (Chromium)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'Chromium'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for Chromium to version 68.0.3440.75 fixes multiple issues.

  Security issues fixed (boo#1102530):

  - CVE-2018-6153: Stack buffer overflow in Skia

  - CVE-2018-6154: Heap buffer overflow in WebGL

  - CVE-2018-6155: Use after free in WebRTC

  - CVE-2018-6156: Heap buffer overflow in WebRTC

  - CVE-2018-6157: Type confusion in WebRTC

  - CVE-2018-6158: Use after free in Blink

  - CVE-2018-6159: Same origin policy bypass in ServiceWorker

  - CVE-2018-6161: Same origin policy bypass in WebAudio

  - CVE-2018-6162: Heap buffer overflow in WebGL

  - CVE-2018-6163: URL spoof in Omnibox

  - CVE-2018-6164: Same origin policy bypass in ServiceWorker

  - CVE-2018-6165: URL spoof in Omnibox

  - CVE-2018-6166: URL spoof in Omnibox

  - CVE-2018-6167: URL spoof in Omnibox

  - CVE-2018-6168: CORS bypass in Blink

  - CVE-2018-6169: Permissions bypass in extension installation

  - CVE-2018-6170: Type confusion in PDFium

  - CVE-2018-6171: Use after free in WebBluetooth

  - CVE-2018-6172: URL spoof in Omnibox

  - CVE-2018-6173: URL spoof in Omnibox

  - CVE-2018-6174: Integer overflow in SwiftShader

  - CVE-2018-6175: URL spoof in Omnibox

  - CVE-2018-6176: Local user privilege escalation in Extensions

  - CVE-2018-6177: Cross origin information leak in Blink

  - CVE-2018-6178: UI spoof in Extensions

  - CVE-2018-6179: Local file information leak in Extensions

  - CVE-2018-6044: Request privilege escalation in Extensions

  - CVE-2018-4117: Cross origin information leak in Blink

  The following user interface changes are included:

  - Chrome will show the 'Not secure' warning on all plain HTTP pages


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-780=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-780=1");
  script_tag(name:"affected", value:"Chromium on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-07/msg00051.html");
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

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~68.0.3440.75~164.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~68.0.3440.75~164.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~68.0.3440.75~164.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~68.0.3440.75~164.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~68.0.3440.75~164.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}