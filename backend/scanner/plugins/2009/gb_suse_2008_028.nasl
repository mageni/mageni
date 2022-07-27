###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2008_028.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for evolution SUSE-SA:2008:028
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
tag_insight = "Multiple buffer overflows have been fixed in Evolution.

  CVE-2008-1108: A buffer overflow in Evolution, when the ITip
  Formatter plugin is disabled, allows remote attackers potentially
  to execute arbitrary code via a long timezone string in an iCalendar
  attachment.

  CVE-2008-1109: A heap-based buffer overflow in Evolution allows
  user-assisted remote attackers to execute arbitrary code via a long
  DESCRIPTION property in an iCalendar attachment, which is not properly
  handled during a reply in the calendar view (aka the Calendars window).";

tag_impact = "remote code execution";
tag_affected = "evolution on openSUSE 10.2, openSUSE 10.3, Novell Linux Desktop 9, SUSE Linux Enterprise Desktop 10 SP1, SLE SDK 10 SP1, SLE SDK 10 SP2, SUSE Linux Enterprise Desktop 10 SP2, SUSE Linux Enterprise 10 SP2 DEBUGINFO";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.309824");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-1108", "CVE-2008-1109");
  script_name( "SuSE Update for evolution SUSE-SA:2008:028");

  script_tag(name:"summary", value:"Check for the Version of evolution");
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

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.12.0~5.8", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.12.0~5.8", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.12.0~5.8", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.8.2~11", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.8.2~11", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.8.2~11", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP1")
{

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.0.4~0.15", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.0.4~0.15", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.0.4~0.15", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.6.0~49.79", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.6.0~49.79", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.6.0~49.79", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-debuginfo", rpm:"evolution-debuginfo~2.6.0~49.79", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.6.0~49.66.6", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.6.0~49.66.6", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.6.0~49.66.6", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9")
{

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.0.4~0.15", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.0.4~0.15", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.0.4~0.15", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.6.0~49.79", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.6.0~49.79", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.6.0~49.79", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-debuginfo", rpm:"evolution-debuginfo~2.6.0~49.79", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.6.0~49.66.6", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.6.0~49.66.6", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.6.0~49.66.6", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLEDe10SP2")
{

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.0.4~0.15", rls:"SLEDe10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.0.4~0.15", rls:"SLEDe10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.0.4~0.15", rls:"SLEDe10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.6.0~49.79", rls:"SLEDe10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.6.0~49.79", rls:"SLEDe10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.6.0~49.79", rls:"SLEDe10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-debuginfo", rpm:"evolution-debuginfo~2.6.0~49.79", rls:"SLEDe10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.6.0~49.66.6", rls:"SLEDe10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.6.0~49.66.6", rls:"SLEDe10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.6.0~49.66.6", rls:"SLEDe10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDK10SP2")
{

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.0.4~0.15", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.0.4~0.15", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.0.4~0.15", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.6.0~49.79", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.6.0~49.79", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.6.0~49.79", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-debuginfo", rpm:"evolution-debuginfo~2.6.0~49.79", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.6.0~49.66.6", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.6.0~49.66.6", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.6.0~49.66.6", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDK10SP1")
{

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.0.4~0.15", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.0.4~0.15", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.0.4~0.15", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.6.0~49.79", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.6.0~49.79", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.6.0~49.79", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-debuginfo", rpm:"evolution-debuginfo~2.6.0~49.79", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.6.0~49.66.6", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.6.0~49.66.6", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.6.0~49.66.6", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP2")
{

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.0.4~0.15", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.0.4~0.15", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.0.4~0.15", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.6.0~49.79", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.6.0~49.79", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.6.0~49.79", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-debuginfo", rpm:"evolution-debuginfo~2.6.0~49.79", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.6.0~49.66.6", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.6.0~49.66.6", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pilot", rpm:"evolution-pilot~2.6.0~49.66.6", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
