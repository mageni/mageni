###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2007_026.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for clamav SUSE-SA:2007:026
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
tag_insight = "The AntiVirus scan engine clamav was updated to version 0.90.2. Among
  other bugs two security problems were fixed which could cause a remote
  denial of service attack against clamav or potentially be used to
  execute code.

  - CVE-2007-1745: The chm_decompress_stream function in
  libclamav/chmunpack.c leaks file descriptors, which has unknown
  impact and attack vectors involving a crafted CHM file.

  - CVE-2007-1997: Integer signedness error in the (1) cab_unstore and
  (2) cab_extract functions in libclamav/cab.c might allow remote
  attackers to execute arbitrary code via a crafted CHM file that
  contains a negative integer, which passes a signed comparison and
  leads to a stack-based buffer overflow.

  Updates for this problem were released on Tuesday  April 17.";

tag_impact = "remote code execution";
tag_affected = "clamav on SUSE LINUX 10.1, openSUSE 10.2, SUSE SLES 9, Open Enterprise Server, Novell Linux POS 9, SUSE SLES 10";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.306917");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2007-1745", "CVE-2007-1997");
  script_name( "SuSE Update for clamav SUSE-SA:2007:026");

  script_tag(name:"summary", value:"Check for the Version of clamav");
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

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90.2~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES10")
{

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90.2~0.1", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90.2~0.2", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLPOS9")
{

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90.2~0.1", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90.2~0.2", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "OES")
{

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90.2~0.1", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90.2~0.2", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES9")
{

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90.2~0.1", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90.2~0.2", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90.2~0.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
