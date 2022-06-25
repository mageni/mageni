###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0704_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for Chromium openSUSE-SU-2018:0704-1 (Chromium)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851718");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-03-17 08:45:38 +0100 (Sat, 17 Mar 2018)");
  script_cve_id("CVE-2017-11215", "CVE-2017-11225", "CVE-2018-6057", "CVE-2018-6060",
                "CVE-2018-6061", "CVE-2018-6062", "CVE-2018-6063", "CVE-2018-6064",
                "CVE-2018-6065", "CVE-2018-6066", "CVE-2018-6067", "CVE-2018-6068",
                "CVE-2018-6069", "CVE-2018-6070", "CVE-2018-6071", "CVE-2018-6072",
                "CVE-2018-6073", "CVE-2018-6074", "CVE-2018-6075", "CVE-2018-6076",
                "CVE-2018-6077", "CVE-2018-6078", "CVE-2018-6079", "CVE-2018-6080",
                "CVE-2018-6081", "CVE-2018-6082", "CVE-2018-6083");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for Chromium openSUSE-SU-2018:0704-1 (Chromium)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'Chromium'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for Chromium to version 65.0.3325.162 fixes the following
  issues:

  - CVE-2017-11215: Use after free in Flash

  - CVE-2017-11225: Use after free in Flash

  - CVE-2018-6060: Use after free in Blink

  - CVE-2018-6061: Race condition in V8

  - CVE-2018-6062: Heap buffer overflow in Skia

  - CVE-2018-6057: Incorrect permissions on shared memory

  - CVE-2018-6063: Incorrect permissions on shared memory

  - CVE-2018-6064: Type confusion in V8

  - CVE-2018-6065: Integer overflow in V8

  - CVE-2018-6066: Same Origin Bypass via canvas

  - CVE-2018-6067: Buffer overflow in Skia

  - CVE-2018-6068: Object lifecycle issues in Chrome Custom Tab

  - CVE-2018-6069: Stack buffer overflow in Skia

  - CVE-2018-6070: CSP bypass through extensions

  - CVE-2018-6071: Heap buffer overflow in Skia

  - CVE-2018-6072: Integer overflow in PDFium

  - CVE-2018-6073: Heap buffer overflow in WebGL

  - CVE-2018-6074: Mark-of-the-Web bypass

  - CVE-2018-6075: Overly permissive cross origin downloads

  - CVE-2018-6076: Incorrect handling of URL fragment identifiers in Blink

  - CVE-2018-6077: Timing attack using SVG filters

  - CVE-2018-6078: URL Spoof in OmniBox

  - CVE-2018-6079: Information disclosure via texture data in WebGL

  - CVE-2018-6080: Information disclosure in IPC call

  - CVE-2018-6081: XSS in interstitials

  - CVE-2018-6082: Circumvention of port blocking

  - CVE-2018-6083: Incorrect processing of AppManifests");
  script_tag(name:"affected", value:"Chromium on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-03/msg00042.html");
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

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~65.0.3325.162~146.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~65.0.3325.162~146.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~65.0.3325.162~146.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~65.0.3325.162~146.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~65.0.3325.162~146.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
