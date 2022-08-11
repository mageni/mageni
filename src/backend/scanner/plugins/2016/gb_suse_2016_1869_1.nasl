###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_1869_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for Chromium openSUSE-SU-2016:1869-1 (Chromium)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851370");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-08-02 10:57:38 +0530 (Tue, 02 Aug 2016)");
  script_cve_id("CVE-2016-1705", "CVE-2016-1706", "CVE-2016-1707", "CVE-2016-1708",
                "CVE-2016-1709", "CVE-2016-1710", "CVE-2016-1711", "CVE-2016-5127",
                "CVE-2016-5128", "CVE-2016-5129", "CVE-2016-5130", "CVE-2016-5131",
                "CVE-2016-5132", "CVE-2016-5133", "CVE-2016-5134", "CVE-2016-5135",
                "CVE-2016-5136", "CVE-2016-5137");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for Chromium openSUSE-SU-2016:1869-1 (Chromium)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'Chromium'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Chromium was updated to 52.0.2743.82 to fix the following security issues
  (boo#989901):

  - CVE-2016-1706: Sandbox escape in PPAPI

  - CVE-2016-1707: URL spoofing on iOS

  - CVE-2016-1708: Use-after-free in Extensions

  - CVE-2016-1709: Heap-buffer-overflow in sfntly

  - CVE-2016-1710: Same-origin bypass in Blink

  - CVE-2016-1711: Same-origin bypass in Blink

  - CVE-2016-5127: Use-after-free in Blink

  - CVE-2016-5128: Same-origin bypass in V8

  - CVE-2016-5129: Memory corruption in V8

  - CVE-2016-5130: URL spoofing

  - CVE-2016-5131: Use-after-free in libxml

  - CVE-2016-5132: Limited same-origin bypass in Service Workers

  - CVE-2016-5133: Origin confusion in proxy authentication

  - CVE-2016-5134: URL leakage via PAC script

  - CVE-2016-5135: Content-Security-Policy bypass

  - CVE-2016-5136: Use after free in extensions

  - CVE-2016-5137: History sniffing with HSTS and CSP

  - CVE-2016-1705: Various fixes from internal audits, fuzzing and other
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

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~52.0.2743.82~61.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~52.0.2743.82~61.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-gnome", rpm:"chromium-desktop-gnome~52.0.2743.82~61.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-kde", rpm:"chromium-desktop-kde~52.0.2743.82~61.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo", rpm:"chromium-ffmpegsumo~52.0.2743.82~61.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
