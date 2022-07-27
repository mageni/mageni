###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2658_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for MozillaThunderbird openSUSE-SU-2018:2658-1 (MozillaThunderbird)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851886");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-09-09 07:10:07 +0200 (Sun, 09 Sep 2018)");
  script_cve_id("CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12361", "CVE-2018-12362",
                "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366",
                "CVE-2018-12367", "CVE-2018-12371", "CVE-2018-5156", "CVE-2018-5187",
                "CVE-2018-5188");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for MozillaThunderbird openSUSE-SU-2018:2658-1 (MozillaThunderbird)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"This update for MozillaThunderbird to version 60.0 fixes the following
  issues:

  These security issues were fixed:

  - CVE-2018-12359: Prevent buffer overflow using computed size of canvas
  element (bsc#1098998).

  - CVE-2018-12360: Prevent use-after-free when using focus() (bsc#1098998).

  - CVE-2018-12361: Prevent integer overflow in SwizzleData (bsc#1098998).

  - CVE-2018-12362: Prevent integer overflow in SSSE3 scaler (bsc#1098998).

  - CVE-2018-5156: Prevent media recorder segmentation fault when track type
  is changed during capture (bsc#1098998).

  - CVE-2018-12363: Prevent use-after-free when appending DOM nodes
  (bsc#1098998).

  - CVE-2018-12364: Prevent CSRF attacks through 307 redirects and NPAPI
  plugins (bsc#1098998).

  - CVE-2018-12365: Prevent compromised IPC child process listing local
  filenames (bsc#1098998).

  - CVE-2018-12371: Prevent integer overflow in Skia library during edge
  builder allocation (bsc#1098998).

  - CVE-2018-12366: Prevent invalid data handling during QCMS
  transformations (bsc#1098998).

  - CVE-2018-12367: Timing attack mitigation of PerformanceNavigationTiming
  (bsc#1098998).

  - CVE-2018-5187: Various memory safety bugs (bsc#1098998).

  - CVE-2018-5188: Various memory safety bugs (bsc#1098998).

  These can not, in general, be exploited through email, but are potential
  risks in browser or browser-like contexts.

  These non-security issues were fixed:

  - Storing of remote content settings fixed (bsc#1084603)

  - Improved message handling and composing

  - Improved handling of message templates

  - Support for OAuth2 and FIDO U2F

  - Various Calendar improvements

  - Various fixes and changes to e-mail workflow

  - Various IMAP fixes

  - Native desktop notifications


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-994=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-994=1");
  script_tag(name:"affected", value:"MozillaThunderbird on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-09/msg00015.html");
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

  if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~60.0~74.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~60.0~74.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~60.0~74.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~60.0~74.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~60.0~74.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~60.0~74.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
