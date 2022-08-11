###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_1993_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for chromium openSUSE-SU-2017:1993-1 (chromium)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851585");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-08-04 12:46:37 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2017-5091", "CVE-2017-5092", "CVE-2017-5093", "CVE-2017-5094",
                "CVE-2017-5095", "CVE-2017-5096", "CVE-2017-5097", "CVE-2017-5098",
                "CVE-2017-5099", "CVE-2017-5100", "CVE-2017-5101", "CVE-2017-5102",
                "CVE-2017-5103", "CVE-2017-5104", "CVE-2017-5105", "CVE-2017-5106",
                "CVE-2017-5107", "CVE-2017-5108", "CVE-2017-5109", "CVE-2017-5110",
                "CVE-2017-7000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for chromium openSUSE-SU-2017:1993-1 (chromium)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update Chromium to version 60.0.3112.78 fixes security issue and bugs.

  The following security issues were fixed:

  * CVE-2017-5091: Use after free in IndexedDB

  * CVE-2017-5092: Use after free in PPAPI

  * CVE-2017-5093: UI spoofing in Blink

  * CVE-2017-5094: Type confusion in extensions

  * CVE-2017-5095: Out-of-bounds write in PDFium

  * CVE-2017-5096: User information leak via Android intents

  * CVE-2017-5097: Out-of-bounds read in Skia

  * CVE-2017-5098: Use after free in V8

  * CVE-2017-5099: Out-of-bounds write in PPAPI

  * CVE-2017-5100: Use after free in Chrome Apps

  * CVE-2017-5101: URL spoofing in OmniBox

  * CVE-2017-5102: Uninitialized use in Skia

  * CVE-2017-5103: Uninitialized use in Skia

  * CVE-2017-5104: UI spoofing in browser

  * CVE-2017-7000: Pointer disclosure in SQLite

  * CVE-2017-5105: URL spoofing in OmniBox

  * CVE-2017-5106: URL spoofing in OmniBox

  * CVE-2017-5107: User information leak via SVG

  * CVE-2017-5108: Type confusion in PDFium

  * CVE-2017-5109: UI spoofing in browser

  * CVE-2017-5110: UI spoofing in payments dialog

  * Various fixes from internal audits, fuzzing and other initiatives

  A number of upstream bugfixes are also included in this release.");
  script_tag(name:"affected", value:"chromium on openSUSE Leap 42.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~60.0.3112.78~104.21.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~60.0.3112.78~104.21.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~60.0.3112.78~104.21.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~60.0.3112.78~104.21.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~60.0.3112.78~104.21.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
