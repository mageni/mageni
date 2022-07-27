###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2007_004.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for krb5 SUSE-SA:2007:004
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
tag_insight = "Various bugs in the Kerberos5 libraries and tools were fixed which
  could be used by remote attackers to crash and potentially execute
  code in kadmind.

  - CVE-2006-6144 / MITKRB5-SA-2006-002: the RPC library could call an
  uninitialized function pointer, which created a security
  vulnerability for kadmind.

  - CVE-2006-6143 / MITKRB5-SA-2006-003: the GSS-API mechglue layer
  could fail to initialize some output pointers, causing callers to
  attempt to free uninitialized pointers.  This caused a security
  vulnerability in kadmind.";

tag_impact = "remote denial of service";
tag_affected = "krb5 on openSUSE 10.2, SUSE LINUX 10.1, SUSE SLED 10, SUSE SLES 10";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.304424");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2006-6143", "CVE-2006-6144");
  script_name( "SuSE Update for krb5 SUSE-SA:2007:004");

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

if(release == "SLED10")
{

  if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.4.3~19.7", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.4.3~19.7", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.4.3~19.7", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.5.1~23.2", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.5.1~23.2", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.5.1~23.2", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES10")
{

  if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.4.3~19.7", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.4.3~19.7", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.4.3~19.7", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.4.3~19.7", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.4.3~19.7", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
