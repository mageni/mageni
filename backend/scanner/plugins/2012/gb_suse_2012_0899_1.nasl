###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_0899_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for MozillaFirefox openSUSE-SU-2012:0899-1 (MozillaFirefox)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850265");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-12-13 17:01:24 +0530 (Thu, 13 Dec 2012)");
  script_cve_id("CVE-2012-1948", "CVE-2012-1949", "CVE-2012-1950", "CVE-2012-1951",
                "CVE-2012-1952", "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955",
                "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1961",
                "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1964", "CVE-2012-1965",
                "CVE-2012-1966", "CVE-2012-1967", "CVE-2012-1960");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Update for MozillaFirefox openSUSE-SU-2012:0899-1 (MozillaFirefox)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.4|openSUSE12\.1)");
  script_tag(name:"affected", value:"MozillaFirefox on openSUSE 12.1, openSUSE 11.4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"MozillaFirefox was updated to 14.0.1 to fix various bugs
  and security issues.


  Following security issues were fixed: MFSA 2012-42: Mozilla
  developers identified and fixed several memory safety bugs
  in the browser engine used in Firefox and other
  Mozilla-based products. Some of these bugs showed evidence
  of memory corruption under certain circumstances, and we
  presume that with enough effort at least some of these
  could be exploited to run arbitrary code.

  CVE-2012-1949: Brian Smith, Gary Kwong, Christian Holler,
  Jesse Ruderman, Christoph Diehl, Chris Jones, Brad Lassey,
  and Kyle Huey reported memory safety problems and crashes
  that affect Firefox 13.

  CVE-2012-1948: Benoit Jacob, Jesse Ruderman, Christian
  Holler, and Bill McCloskey reported memory safety problems
  and crashes that affect Firefox ESR 10 and Firefox 13.


  MFSA 2012-43 / CVE-2012-1950: Security researcher Mario
  Gomes andresearch firm Code Audit Labs reported a mechanism
  to short-circuit page loads through drag and drop to the
  addressbar by canceling the page load. This causes the
  address of the previously site entered to be displayed in
  the addressbar instead of the currently loaded page. This
  could lead to potential phishing attacks on users.

  MFSA 2012-44 Google security researcher Abhishek Arya used
  the Address Sanitizer tool to uncover four issues: two
  use-after-free problems, one out of bounds read bug, and a
  bad cast. The first use-after-free problem is caused when
  an array of nsSMILTimeValueSpec objects is destroyed but
  attempts are made to call into objects in this array later.
  The second use-after-free problem is in
  nsDocument::AdoptNode when it adopts into an empty document
  and then adopts into another document, emptying the first
  one. The heap buffer overflow is in ElementAnimations when
  data is read off of end of an array and then pointers are
  dereferenced. The bad cast happens when
  nsTableFrame::InsertFrames is called with frames in
  aFrameList that are a mix of row group frames and column
  group frames. AppendFrames is not able to handle this mix.

  All four of these issues are potentially exploitable.
  CVE-2012-1951: Heap-use-after-free in
  nsSMILTimeValueSpec::IsEventBased CVE-2012-1954:
  Heap-use-after-free in nsDocument::AdoptNode CVE-2012-1953:
  Out of bounds read in ElementAnimations::EnsureStyleRuleFor
  CVE-2012-1952: Bad cast in nsTableFrame::InsertFrames


  MFSA 2012-45 / CVE-2012-1955: Security researcher Mariusz
  Mlynski reported an issue with spoofing of the location
  property. In this issue, calls ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~14.0.1~28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~14.0.1~28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~14.0.1~28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~14.0.1~28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~14.0.1~28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~14.0.1~28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~14.0.1~28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~14.0.1~28.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSE12.1")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~14.0.1~2.33.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~14.0.1~2.33.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~14.0.1~2.33.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~14.0.1~2.33.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~14.0.1~2.33.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~14.0.1~2.33.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~14.0.1~2.33.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~14.0.1~2.33.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
