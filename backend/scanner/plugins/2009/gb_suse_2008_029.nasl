###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2008_029.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for opera SUSE-SA:2008:029
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "The Opera web browser was brought to security update level 9.50

  Following security problems were fixed:

  CVE-2008-2714: Opera before 9.26 allows remote attackers to
  misrepresent web page addresses using &quot;certain characters&quot; that
  &quot;cause the page address text to be misplaced.&quot;

  CVE-2008-2715: Unspecified vulnerability in Opera before 9.5 allows
  remote attackers to read cross-domain images via HTML CANVAS elements
  that use the images as patterns.

  CVE-2008-2716: Unspecified vulnerability in Opera before 9.5 allows
  remote attackers to spoof the contents of trusted frames on the same
  parent page by modifying the location, which can facilitate phishing
  attacks.

  Opera 9.50 also contains lots of new features and other bugfixes,
  see the Changelog at:

  http://www.opera.com/docs/changelogs/linux/950/";

tag_impact = "web page spoofing, address misrepresenting";
tag_affected = "opera on openSUSE 10.2, openSUSE 10.3, openSUSE 11.0";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.307769");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-2714", "CVE-2008-2715", "CVE-2008-2716");
  script_name( "SuSE Update for opera SUSE-SA:2008:029");

  script_tag(name:"summary", value:"Check for the Version of opera");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE10.3")
{

  if ((res = isrpmvuln(pkg:"opera", rpm:"opera~9.50~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"opera", rpm:"opera~9.50~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE11.0")
{

  if ((res = isrpmvuln(pkg:"opera", rpm:"opera~9.50~0.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
