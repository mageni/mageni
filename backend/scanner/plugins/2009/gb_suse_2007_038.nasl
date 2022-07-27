###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2007_038.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for krb5 SUSE-SA:2007:038
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
tag_insight = "The KRB5 libraries and utilities contained two security problems for which updates
  were released.

  - CVE-2007-2798: A stack-based buffer overflow in kadmind was fixed
  which can be exploited by authenticated remote users to gain
  root. This requires kadmind to run to be effective.

  - CVE-2007-2443: Additionally two bugs in the RPC library
  of kadmind were fixed that can lead to remote system compromise. Note
  that third-party applications using this RPC library are vulnerable
  too.";

tag_impact = "remote code execution";
tag_affected = "krb5 on SUSE LINUX 10.1, openSUSE 10.2, SUSE Linux Enterprise Desktop 10 SP1, SLE SDK 10 SP1, SUSE Linux Enterprise Server 10 SP1";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.308175");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-2442", "CVE-2007-2443", "CVE-2007-2798");
  script_name( "SuSE Update for krb5 SUSE-SA:2007:038");

  script_tag(name:"summary", value:"Check for the Version of krb5");
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

if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.5.1~23.6", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.5.1~23.6", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.5.1~23.6", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.5.1~23.6", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-devel-32bit", rpm:"krb5-devel-32bit~1.5.1~23.6", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "LES10SP1")
{

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.4.3~19.22", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.4.3~19.22", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.4.3~19.22", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.4.3~19.22", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-devel-32bit", rpm:"krb5-devel-32bit~1.4.3~19.22", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDK10SP1")
{

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.4.3~19.22", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.4.3~19.22", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.4.3~19.22", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.4.3~19.22", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-devel-32bit", rpm:"krb5-devel-32bit~1.4.3~19.22", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP1")
{

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.4.3~19.22", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.4.3~19.22", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.4.3~19.22", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.4.3~19.22", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-devel-32bit", rpm:"krb5-devel-32bit~1.4.3~19.22", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.4.3~19.22", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.4.3~19.22", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.4.3~19.22", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
