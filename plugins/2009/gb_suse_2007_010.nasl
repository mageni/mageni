###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2007_010.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for IBMJava2 SUSE-SA:2007:010
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
tag_insight = "Various security problems and bugs have been fixed in the IBMJava
  JRE and SDK.

  The IBM Java packages were updated to:
  - IBM Java 1.4.2 to Service Refresh 7.
  - IBM JAVA 1.3.10 to Service Refresh 10.

  It contains several security fixes also fixed in SUN Java including:

  - CVE-2006-4339: fix for the RSA exponent padding attack.
  - CVE-2006-6737: 2 unspecified vulnerabilities that
  allow untrusted applets to access data in other applets.
  - CVE-2006-6745: Multiple unspecified vulnerabilities that allow
  applets to gain privileges related to serialization bugs in the JRE.
  - CVE-2006-6731: Multiple buffer overflows in java image handling
  routines that allow attackers to potentially read/write/execute
  local files.

  A full overview is at:
  http://www-128.ibm.com/developerworks/java/jdk/alerts/

  The update also contains important timezone updates:
  - US daylight saving time update starting 2007.
  - Western Australia daylight savings time introduction in December 2006.
  - A general update to current timezone data-set.";

tag_impact = "remote code execution";
tag_affected = "IBMJava2 on SuSE Linux Enterprise Server 8, SUSE SLES 9, Open Enterprise Server, Novell Linux POS 9, SUSE SLES 10";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.306278");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2006-4339", "CVE-2006-4790", "CVE-2006-6731", "CVE-2006-6736", "CVE-2006-6737", "CVE-2006-6745");
  script_name( "SuSE Update for IBMJava2 SUSE-SA:2007:010");

  script_tag(name:"summary", value:"Check for the Version of IBMJava2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms");
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

if(release == "OES")
{

  if ((res = isrpmvuln(pkg:"IBMJava2-JRE", rpm:"IBMJava2-JRE~1.4.2~0.76", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"IBMJava2-SDK", rpm:"IBMJava2-SDK~1.4.2~0.76", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES9")
{

  if ((res = isrpmvuln(pkg:"IBMJava2-JRE", rpm:"IBMJava2-JRE~1.4.2~0.76", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"IBMJava2-SDK", rpm:"IBMJava2-SDK~1.4.2~0.76", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES10")
{

  if ((res = isrpmvuln(pkg:"java-1_4_2-ibm", rpm:"java-1_4_2-ibm~1.4.2.s4~23.10", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-ibm-devel", rpm:"java-1_4_2-ibm-devel~1.4.2.s4~23.10", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-ibm-jdbc", rpm:"java-1_4_2-ibm-jdbc~1.4.2.s4~23.10", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-ibm-plugin", rpm:"java-1_4_2-ibm-plugin~1.4.2.s4~23.10", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESSr8")
{

  if ((res = isrpmvuln(pkg:"IBMJava2-JRE", rpm:"IBMJava2-JRE~1.3.1~237", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"IBMJava2-SDK", rpm:"IBMJava2-SDK~1.3.1~237", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLPOS9")
{

  if ((res = isrpmvuln(pkg:"IBMJava2-JRE", rpm:"IBMJava2-JRE~1.4.2~0.76", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"IBMJava2-SDK", rpm:"IBMJava2-SDK~1.4.2~0.76", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
