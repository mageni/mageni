###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1484_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for chromium openSUSE-SU-2018:1484-1 (chromium)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851772");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-06-05 14:03:22 +0530 (Tue, 05 Jun 2018)");
  script_cve_id("CVE-2018-6123", "CVE-2018-6124", "CVE-2018-6125", "CVE-2018-6126",
                "CVE-2018-6127", "CVE-2018-6128", "CVE-2018-6129", "CVE-2018-6130",
                "CVE-2018-6131", "CVE-2018-6132", "CVE-2018-6133", "CVE-2018-6134",
                "CVE-2018-6135", "CVE-2018-6136", "CVE-2018-6137", "CVE-2018-6138",
                "CVE-2018-6139", "CVE-2018-6140", "CVE-2018-6141", "CVE-2018-6142",
                "CVE-2018-6143", "CVE-2018-6144", "CVE-2018-6145", "CVE-2018-6147");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for chromium openSUSE-SU-2018:1484-1 (chromium)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"This update for chromium to version 66.0.3359.181 fixes the following
  issues:

  The following security issues were fixed (boo#1095163):

  * CVE-2018-6123: Use after free in Blink.

  * CVE-2018-6124: Type confusion in Blink.

  * CVE-2018-6125: Overly permissive policy in WebUSB.

  * CVE-2018-6126: Heap buffer overflow in Skia.

  * CVE-2018-6127: Use after free in indexedDB.

  * CVE-2018-6128: uXSS in Chrome on iOS.

  * CVE-2018-6129: Out of bounds memory access in WebRTC.

  * CVE-2018-6130: Out of bounds memory access in WebRTC.

  * CVE-2018-6131: Incorrect mutability protection in WebAssembly.

  * CVE-2018-6132: Use of uninitialized memory in WebRTC.

  * CVE-2018-6133: URL spoof in Omnibox.

  * CVE-2018-6134: Referrer Policy bypass in Blink.

  * CVE-2018-6135: UI spoofing in Blink.

  * CVE-2018-6136: Out of bounds memory access in V8.

  * CVE-2018-6137: Leak of visited status of page in Blink.

  * CVE-2018-6138: Overly permissive policy in Extensions.

  * CVE-2018-6139: Restrictions bypass in the debugger extension API.

  * CVE-2018-6140: Restrictions bypass in the debugger extension API.

  * CVE-2018-6141: Heap buffer overflow in Skia.

  * CVE-2018-6142: Out of bounds memory access in V8.

  * CVE-2018-6143: Out of bounds memory access in V8.

  * CVE-2018-6144: Out of bounds memory access in PDFium.

  * CVE-2018-6145: Incorrect escaping of MathML in Blink.

  * CVE-2018-6147: Password fields not taking advantage of OS protections in
  Views.

  Additional changes:

  * Autoplay: Force enable on desktop for Web Audio

  This update enables the 'Strict site isolation' feature for a larger
  percentage of users. This feature is a mitigation against the Spectre
  vulnerabilities. It can be turned on via:
  chrome://flags/#enable-site-per-process It can be disabled via:
  chrome://flags/#site-isolation-trial-opt-out


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-546=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-546=1");
  script_tag(name:"affected", value:"chromium on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-06/msg00000.html");
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

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~67.0.3396.62~161.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~67.0.3396.62~161.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~67.0.3396.62~161.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~67.0.3396.62~161.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~67.0.3396.62~161.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
