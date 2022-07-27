###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for java-1.6.0-openjdk MDVSA-2011:054 (java-1.6.0-openjdk)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-03/msg00013.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831354");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-04-01 15:34:04 +0200 (Fri, 01 Apr 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-4351", "CVE-2010-4448", "CVE-2010-4450", "CVE-2010-4465", "CVE-2010-4469", "CVE-2010-4470", "CVE-2010-4471", "CVE-2010-4472", "CVE-2010-4476", "CVE-2011-0025", "CVE-2011-0706");
  script_name("Mandriva Update for java-1.6.0-openjdk MDVSA-2011:054 (java-1.6.0-openjdk)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.6.0-openjdk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(mes5|2010\.1|2010\.0|2009\.0)");
  script_tag(name:"affected", value:"java-1.6.0-openjdk on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been identified and fixed in
  java-1.6.0-openjdk:

  The JNLP SecurityManager in IcedTea (IcedTea.so) 1.7 before 1.7.7,
  1.8 before 1.8.4, and 1.9 before 1.9.4 for Java OpenJDK returns from
  the checkPermission method instead of throwing an exception in certain
  circumstances, which might allow context-dependent attackers to bypass
  the intended security policy by creating instances of ClassLoader
  (CVE-2010-4351).

  Unspecified vulnerability in the Java Runtime Environment (JRE)
  in Oracle Java SE and Java for Business 6 Update 23 and earlier,
  5.0 Update 27 and earlier, and 1.4.2_29 earlier allows remote
  untrusted Java Web Start applications and untrusted Java applets to
  affect integrity via unknown vectors related to Networking. NOTE: the
  previous information was obtained from the February 2011 CPU. Oracle
  has not commented on claims from a downstream vendor that this issue
  involves DNS cache poisoning by untrusted applets. (CVE-2010-4448)

  Unspecified vulnerability in the Java Runtime Environment (JRE)
  in Oracle Java SE and Java for Business 6 Update 23 and earlier for
  Solaris and Linux, 5.0 Update 27 and earlier for Solaris and Linux,
  and 1.4.2_29 and earlier for Solaris and Linux allows local standalone
  applications to affect confidentiality, integrity, and availability via
  unknown vectors related to Launcher. NOTE: the previous information was
  obtained from the February 2011 CPU. Oracle has not commented on claims
  from a downstream vendor that this issue is an untrusted search path
  vulnerability involving an empty LD_LIBRARY_PATH environment variable
  (CVE-2010-4450).

  Unspecified vulnerability in the Java Runtime Environment (JRE)
  in Oracle Java SE and Java for Business 6 Update 23 and earlier,
  5.0 Update 27 and earlier, and 1.4.2_29 and earlier allows remote
  untrusted Java Web Start applications and untrusted Java applets to
  affect confidentiality, integrity, and availability via unknown vectors
  related to Swing. NOTE: the previous information was obtained from the
  February 2011 CPU. Oracle has not commented on claims from a downstream
  vendor that this issue is related to the lack of framework support by
  AWT event dispatch, and/or clipboard access in Applets. (CVE-2010-4465)

  Unspecified vulnerability in the Java Runtime Environment (JRE)
  in Oracle Java  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"java-1.5.0-gcj-1.5.0.0", rpm:"java-1.5.0-gcj-1.5.0.0~17.1.7.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.5.0-gcj-devel", rpm:"java-1.5.0-gcj-devel~1.5.0.0~17.1.7.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.5.0-gcj-javadoc", rpm:"java-1.5.0-gcj-javadoc~1.5.0.0~17.1.7.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.5.0-gcj-src", rpm:"java-1.5.0-gcj-src~1.5.0.0~17.1.7.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~7.b18.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~7.b18.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~7.b18.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

   if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-plugin", rpm:"java-1.6.0-openjdk-plugin~1.6.0.0~7.b18.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~7.b18.5mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.5.0-gcj-1.5.0.0", rpm:"java-1.5.0-gcj-1.5.0.0-17.1.7.1mdv2009.0", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~7.b18.5mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~7.b18.5mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~7.b18.5mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~7.b18.5mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-plugin", rpm:"java-1.6.0-openjdk-plugin~1.6.0.0~7.b18.5mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ava-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~7.b18.5mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-1.6.0.0", rpm:"java-1.6.0-openjdk-1.6.0.0~7.b18.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~7.b18.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~7.b18.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~7.b18.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-plugin", rpm:"java-1.6.0-openjdk-plugin~1.6.0.0~7.b18.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~7.b18.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"java-1.5.0-gcj-1.5.0.0", rpm:"java-1.5.0-gcj-1.5.0.0~17.1.7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.5.0-gcj-devel", rpm:"java-1.5.0-gcj-devel~1.5.0.0~17.1.7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.5.0-gcj-javadoc", rpm:"java-1.5.0-gcj-javadoc~1.5.0.0~17.1.7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.5.0-gcj-src", rpm:"java-1.5.0-gcj-src~1.5.0.0~17.1.7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~7.b18.5mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~7.b18.5mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~7.b18.5mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~7.b18.5mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-plugin", rpm:"java-1.6.0-openjdk-plugin~1.6.0.0~7.b18.5mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~7.b18.5mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
