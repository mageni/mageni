###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2008_025.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for IBMJava2,IBMJava5,java-1_4_2-ibm,java-1_5_0-ibm SUSE-SA:2008:025
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
tag_insight = "IBM Java 1.4.2 was updated to SR10 and IBM Java 1.5.0 was updated to
  SR7 to fix various security issues:

  - CVE-2008-1196: A buffer overflow vulnerability in Java Web Start
  may allow an untrusted Java Web Start application that is downloaded
  from a website to elevate its privileges. For example, an untrusted
  Java Web Start application may grant itself permissions to read and
  write local files or execute local applications that are accessible
  to the user running the untrusted application.

  - CVE-2008-1195: A vulnerability in the Java Runtime Environment may
  allow JavaScript(TM) code that is downloaded by a browser to make
  connections to network services on the system that the browser runs
  on, through Java APIs, This may allow files (that are accessible
  through these network services) or vulnerabilities (that exist on
  these network services) which are not otherwise normally accessible
  to be accessed or exploited.

  - CVE-2008-1192: A vulnerability in the Java Plug-in may an untrusted
  applet to bypass same origin policy and leverage this flaw to
  execute local applications that are accessible to the user running
  the untrusted applet.

  - CVE-2008-1190: A vulnerability in Java Web Start may allow an
  untrusted Java Web Start application to elevate its privileges. For
  example, an application may grant itself permissions to read and
  write local files or execute local applications that are accessible
  to the user running the untrusted application.

  - CVE-2008-1189: A buffer overflow vulnerability in the Java Runtime
  Environment may allow an untrusted applet or application to elevate
  its privileges. For example, an applet may grant itself permissions
  to read and write local files or execute local applications that
  are accessible to the user running the untrusted applet.

  - CVE-2008-1187: A vulnerability in the Java Runtime Environment
  with parsing XML data may allow an untrusted applet or application
  to elevate its privileges. For example, an applet may read certain
  URL resources (such as some files and web pages).

  - CVE-2007-5232: A vulnerability in the Java Runtime Environment (JRE)
  with applet caching may allow an untrusted applet that is
  downloaded from a malicious website to make network connections ... 

  Description truncated, for more information please check the Reference URL";

tag_impact = "remote code execution";
tag_affected = "IBMJava2,IBMJava5,java-1_4_2-ibm,java-1_5_0-ibm on SUSE SLES 9, Open Enterprise Server, Novell Linux POS 9, SUSE Linux Enterprise Desktop 10 SP1, SLE SDK 10 SP1, SUSE Linux Enterprise Server 10 SP1";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.308929");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-3698", "CVE-2007-4381", "CVE-2007-5232", "CVE-2007-5236", "CVE-2007-5238", "CVE-2007-5239", "CVE-2007-5240", "CVE-2007-5273", "CVE-2007-5274", "CVE-2008-0657", "CVE-2008-1187", "CVE-2008-1188", "CVE-2008-1189", "CVE-2008-1190", "CVE-2008-1192", "CVE-2008-1193", "CVE-2008-1194", "CVE-2008-1195", "CVE-2008-1196");
  script_name( "SuSE Update for IBMJava2,IBMJava5,java-1_4_2-ibm,java-1_5_0-ibm SUSE-SA:2008:025");

  script_tag(name:"summary", value:"Check for the Version of IBMJava2,IBMJava5,java-1_4_2-ibm,java-1_5_0-ibm");
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

if(release == "SLESDK10SP1")
{

  if ((res = isrpmvuln(pkg:"java-1_4_2-ibm", rpm:"java-1_4_2-ibm~1.4.2_sr10~0.2", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-ibm-devel", rpm:"java-1_4_2-ibm-devel~1.4.2_sr10~0.2", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-ibm-jdbc", rpm:"java-1_4_2-ibm-jdbc~1.4.2_sr10~0.2", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-ibm-plugin", rpm:"java-1_4_2-ibm-plugin~1.4.2_sr10~0.2", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLPOS9")
{

  if ((res = isrpmvuln(pkg:"IBMJava5-JRE", rpm:"IBMJava5-JRE~1.5.0~0.22", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"IBMJava5-SDK", rpm:"IBMJava5-SDK~1.5.0~0.22", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"IBMJava2-JRE", rpm:"IBMJava2-JRE~1.4.2~0.112", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"IBMJava2-SDK", rpm:"IBMJava2-SDK~1.4.2~0.112", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "OES")
{

  if ((res = isrpmvuln(pkg:"IBMJava5-JRE", rpm:"IBMJava5-JRE~1.5.0~0.22", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"IBMJava5-SDK", rpm:"IBMJava5-SDK~1.5.0~0.22", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"IBMJava2-JRE", rpm:"IBMJava2-JRE~1.4.2~0.112", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"IBMJava2-SDK", rpm:"IBMJava2-SDK~1.4.2~0.112", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES9")
{

  if ((res = isrpmvuln(pkg:"IBMJava5-JRE", rpm:"IBMJava5-JRE~1.5.0~0.22", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"IBMJava5-SDK", rpm:"IBMJava5-SDK~1.5.0~0.22", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"IBMJava2-JRE", rpm:"IBMJava2-JRE~1.4.2~0.112", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"IBMJava2-SDK", rpm:"IBMJava2-SDK~1.4.2~0.112", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "LES10SP1")
{

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm", rpm:"java-1_5_0-ibm~1.5.0_sr7~0.2", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm-32bit", rpm:"java-1_5_0-ibm-32bit~1.5.0_sr7~0.2", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm-alsa-32bit", rpm:"java-1_5_0-ibm-alsa-32bit~1.5.0_sr7~0.2", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm-devel", rpm:"java-1_5_0-ibm-devel~1.5.0_sr7~0.2", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm-devel-32bit", rpm:"java-1_5_0-ibm-devel-32bit~1.5.0_sr7~0.2", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm-fonts", rpm:"java-1_5_0-ibm-fonts~1.5.0_sr7~0.2", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm-alsa", rpm:"java-1_5_0-ibm-alsa~1.5.0_sr7~0.2", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm-jdbc", rpm:"java-1_5_0-ibm-jdbc~1.5.0_sr7~0.2", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm-plugin", rpm:"java-1_5_0-ibm-plugin~1.5.0_sr7~0.2", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm-demo", rpm:"java-1_5_0-ibm-demo~1.5.0_sr7~0.2", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm-src", rpm:"java-1_5_0-ibm-src~1.5.0_sr7~0.2", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-ibm", rpm:"java-1_4_2-ibm~1.4.2_sr10~0.2", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-ibm-devel", rpm:"java-1_4_2-ibm-devel~1.4.2_sr10~0.2", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-ibm-jdbc", rpm:"java-1_4_2-ibm-jdbc~1.4.2_sr10~0.2", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-ibm-plugin", rpm:"java-1_4_2-ibm-plugin~1.4.2_sr10~0.2", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP1")
{

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm", rpm:"java-1_5_0-ibm~1.5.0_sr7~0.2", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm-32bit", rpm:"java-1_5_0-ibm-32bit~1.5.0_sr7~0.2", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm-alsa-32bit", rpm:"java-1_5_0-ibm-alsa-32bit~1.5.0_sr7~0.2", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm-devel", rpm:"java-1_5_0-ibm-devel~1.5.0_sr7~0.2", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm-devel-32bit", rpm:"java-1_5_0-ibm-devel-32bit~1.5.0_sr7~0.2", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm-fonts", rpm:"java-1_5_0-ibm-fonts~1.5.0_sr7~0.2", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm-alsa", rpm:"java-1_5_0-ibm-alsa~1.5.0_sr7~0.2", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm-jdbc", rpm:"java-1_5_0-ibm-jdbc~1.5.0_sr7~0.2", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm-plugin", rpm:"java-1_5_0-ibm-plugin~1.5.0_sr7~0.2", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm-demo", rpm:"java-1_5_0-ibm-demo~1.5.0_sr7~0.2", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-ibm-src", rpm:"java-1_5_0-ibm-src~1.5.0_sr7~0.2", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
