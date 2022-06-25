###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_4056_1.nasl 13072 2019-01-15 08:12:06Z asteins $
#
# SuSE Update for Chromium openSUSE-SU-2018:4056-1 (Chromium)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852166");
  script_version("$Revision: 13072 $");
  script_cve_id("CVE-2018-17480", "CVE-2018-17481", "CVE-2018-18335",
                "CVE-2018-18336", "CVE-2018-18337", "CVE-2018-18338", "CVE-2018-18339",
                "CVE-2018-18340", "CVE-2018-18341", "CVE-2018-18342", "CVE-2018-18343",
                "CVE-2018-18344", "CVE-2018-18345", "CVE-2018-18346", "CVE-2018-18347",
                "CVE-2018-18348", "CVE-2018-18349", "CVE-2018-18350", "CVE-2018-18351",
                "CVE-2018-18352", "CVE-2018-18353", "CVE-2018-18354", "CVE-2018-18355",
                "CVE-2018-18356", "CVE-2018-18357", "CVE-2018-18358", "CVE-2018-18359");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-01-15 09:12:06 +0100 (Tue, 15 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-12-10 07:37:32 +0100 (Mon, 10 Dec 2018)");
  script_name("SuSE Update for Chromium openSUSE-SU-2018:4056-1 (Chromium)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-12/msg00023.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Chromium'
  package(s) announced via the openSUSE-SU-2018:4056_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update to Chromium version 71.0.3578.80
  fixes security issues and bugs.

  Security issues fixed (boo#1118529):

  - CVE-2018-17480: Out of bounds write in V8

  - CVE-2018-17481: Use after frees in PDFium

  - CVE-2018-18335: Heap buffer overflow in Skia

  - CVE-2018-18336: Use after free in PDFium

  - CVE-2018-18337: Use after free in Blink

  - CVE-2018-18338: Heap buffer overflow in Canvas

  - CVE-2018-18339: Use after free in WebAudio

  - CVE-2018-18340: Use after free in MediaRecorder

  - CVE-2018-18341: Heap buffer overflow in Blink

  - CVE-2018-18342: Out of bounds write in V8

  - CVE-2018-18343: Use after free in Skia

  - CVE-2018-18344: Inappropriate implementation in Extensions

  - Multiple issues in SQLite via WebSQL

  - CVE-2018-18345: Inappropriate implementation in Site Isolation

  - CVE-2018-18346: Incorrect security UI in Blink

  - CVE-2018-18347: Inappropriate implementation in Navigation

  - CVE-2018-18348: Inappropriate implementation in Omnibox

  - CVE-2018-18349: Insufficient policy enforcement in Blink

  - CVE-2018-18350: Insufficient policy enforcement in Blink

  - CVE-2018-18351: Insufficient policy enforcement in Navigation

  - CVE-2018-18352: Inappropriate implementation in Media

  - CVE-2018-18353: Inappropriate implementation in Network Authentication

  - CVE-2018-18354: Insufficient data validation in Shell Integration

  - CVE-2018-18355: Insufficient policy enforcement in URL Formatter

  - CVE-2018-18356: Use after free in Skia

  - CVE-2018-18357: Insufficient policy enforcement in URL Formatter

  - CVE-2018-18358: Insufficient policy enforcement in Proxy

  - CVE-2018-18359: Out of bounds read in V8

  - Inappropriate implementation in PDFium

  - Use after free in Extensions

  - Inappropriate implementation in Navigation

  - Insufficient policy enforcement in Navigation

  - Insufficient policy enforcement in URL Formatter

  - Various fixes from internal audits, fuzzing and other initiatives

  The following changes are included:

  - advertisements posing as error messages are now blocked

  - Automatic playing of content at page load mostly disabled

  - New JavaScript API for relative time display


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1521=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2018-1521=1");

  script_tag(name:"affected", value:"Chromium on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~71.0.3578.80~lp150.2.30.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~71.0.3578.80~lp150.2.30.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~71.0.3578.80~lp150.2.30.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~71.0.3578.80~lp150.2.30.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~71.0.3578.80~lp150.2.30.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
