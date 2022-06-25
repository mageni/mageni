###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1833_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for MozillaFirefox openSUSE-SU-2018:1833-1 (MozillaFirefox)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851800");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-06-29 05:46:47 +0200 (Fri, 29 Jun 2018)");
  script_cve_id("CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12361", "CVE-2018-12362",
                "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366",
                "CVE-2018-12367", "CVE-2018-12369", "CVE-2018-12371", "CVE-2018-5156",
                "CVE-2018-5187", "CVE-2018-5188");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for MozillaFirefox openSUSE-SU-2018:1833-1 (MozillaFirefox)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"This security update for MozillaFirefox to version 60.1.0esr fixes
  multiple issues.

  Security issues fixed (MFSA 2018-16, boo#1098998):

  - CVE-2018-12359: Buffer overflow using computed size of canvas element

  - CVE-2018-12360: Use-after-free when using focus()

  - CVE-2018-12361: Integer overflow in SwizzleData

  - CVE-2018-12362: Integer overflow in SSSE3 scaler

  - CVE-2018-5156: Media recorder segmentation fault when track type is
  changed during capture

  - CVE-2018-12363: Use-after-free when appending DOM nodes

  - CVE-2018-12364: CSRF attacks through 307 redirects and NPAPI plugins

  - CVE-2018-12365: Compromised IPC child process can list local filenames

  - CVE-2018-12371: Integer overflow in Skia library during edge builder
  allocation

  - CVE-2018-12366: Invalid data handling during QCMS transformations

  - CVE-2018-12367: Timing attack mitigation of PerformanceNavigationTiming

  - CVE-2018-12369: WebExtension security permission checks bypassed by
  embedded experiments

  - CVE-2018-5187: Memory safety bugs fixed in Firefox 60 and Firefox ESR
  60.1

  - CVE-2018-5188: Memory safety bugs fixed in Firefox 60, Firefox ESR 60.1,
  and Firefox ESR 52.9

  Other issues fixed:

  - various stability and regression fixes

  - do not disable system installed unsigned language packs (bmo#1464766)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-676=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-676=1");
  script_tag(name:"affected", value:"MozillaFirefox on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-06/msg00048.html");
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

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~60.1.0~106.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~60.1.0~106.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~60.1.0~106.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~60.1.0~106.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~60.1.0~106.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~60.1.0~106.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~60.1.0~106.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~60.1.0~106.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
