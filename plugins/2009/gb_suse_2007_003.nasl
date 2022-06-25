###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2007_003.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for Sun Java SUSE-SA:2007:003
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
tag_insight = "The SUN Java packages have been upgraded to fix security problems.

  SUN Java was upgraded on all affected distributions:

  - The Java 1.3 version to 1.3.1_19 for SUSE Linux Enterprise Server 8.

  - The Java 1.4 version (also known as Java 2) to 1.4.2_13 for SUSE
  Linux Enterprise Desktop 1, SUSE Linux Enterprise Server 9, SUSE
  Linux 9.3, 10.0, 10.1 and openSUSE 10.2.

  - The Java 1.5 version (also known as Java 5) to 1.5.0_10 for SUSE
  Linux 9.3, 10.0, 10.1 and openSUSE 10.2.

  While Sun does not publish the vulnerabilities fixed for this specific
  update, it published the bugs fixed previously, text snippets verbatim
  from the Mitre CVE DB:

  CVE-2006-6731:Multiple buffer overflows in Sun Java Development
  Kit (JDK) and Java Runtime Environment (JRE) 5.0 Update 7 and
  earlier, Java System Development Kit (SDK) and JRE 1.4.2_12 and
  earlier 1.4.x versions, and SDK and JRE 1.3.1_18 and earlier
  allow attackers to develop Java applets that read, write, or
  execute local files, possibly related to (1) integer overflows in
  the Java_sun_awt_image_ImagingLib_convolveBI, awt_parseRaster,
  and awt_parseColorModel functions; (2) a stack overflow in
  the Java_sun_awt_image_ImagingLib_lookupByteRaster function;
  and (3) improper handling of certain negative values in the
  Java_sun_font_SunLayoutEngine_nativeLayout function.

  CVE-2006-6736: Unspecified vulnerability in Sun Java Development Kit
  (JDK) and Java Runtime Environment (JRE) 5.0 Update 6 and earlier,
  Java System Development Kit (SDK) and JRE 1.4.2_12 and earlier 1.4.x
  versions, and SDK and JRE 1.3.1_18 and earlier allows attackers to
  attackers to use untrusted applets to &quot;access data in other applets,&quot;
  aka &quot;The second issue.&quot;

  CVE-2006-6737: Unspecified vulnerability in Sun Java Development Kit
  (JDK) and Java Runtime Environment (JRE) 5.0 Update 5 and earlier,
  Java System Development Kit (SDK) and JRE 1.4.2_10 and earlier 1.4.x
  versions, and SDK and JRE 1.3.1_18 and earlier allows attackers to
  use untrusted applets to &quot;access data in other applets,&quot; aka &quot;The
  first issue.&quot;

  CVE-2006-6745: Multiple unspecified vulnerabilities in Sun Java
  Development Kit (JDK) and Java Runtime Environment (JRE) 5.0 Update
  7 and earlier, and Java System Development Kit (SDK) and JRE 1.4.2_12
  and earlier 1.4.x versions, allow attackers to develop Java applets or
  applications that are able to gain privileges, related to serialization
  in JRE.";

tag_impact = "remote code execution";
tag_affected = "Sun Java on Novell Linux Desktop 9, Novell Linux POS 9, Open Enterprise Server, openSUSE 10.2, SUSE LINUX 10.1, SuSE Linux Enterprise Server 8, SUSE SLED 10, SUSE SLES 10, SUSE SLES 9";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.305094");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2006-6731", "CVE-2006-6736", "CVE-2006-6737", "CVE-2006-6745");
  script_name( "SuSE Update for Sun Java SUSE-SA:2007:003");

  script_tag(name:"summary", value:"Check for the Version of Sun Java");
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

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun", rpm:"java-1_4_2-sun~1.4.2_update13~3.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-alsa", rpm:"java-1_4_2-sun-alsa~1.4.2_update13~3.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-devel", rpm:"java-1_4_2-sun-devel~1.4.2_update13~3.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-jdbc", rpm:"java-1_4_2-sun-jdbc~1.4.2_update13~3.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-plugin", rpm:"java-1_4_2-sun-plugin~1.4.2_update13~3.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-sun", rpm:"java-1_5_0-sun~1.5.0_update10~2.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-sun-alsa", rpm:"java-1_5_0-sun-alsa~1.5.0_update10~2.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-sun-devel", rpm:"java-1_5_0-sun-devel~1.5.0_update10~2.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-sun-jdbc", rpm:"java-1_5_0-sun-jdbc~1.5.0_update10~2.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-sun-plugin", rpm:"java-1_5_0-sun-plugin~1.5.0_update10~2.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES10")
{

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun", rpm:"java-1_4_2-sun~1.4.2.13~0.2", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-alsa", rpm:"java-1_4_2-sun-alsa~1.4.2.13~0.2", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-demo", rpm:"java-1_4_2-sun-demo~1.4.2.13~0.2", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-devel", rpm:"java-1_4_2-sun-devel~1.4.2.13~0.2", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-jdbc", rpm:"java-1_4_2-sun-jdbc~1.4.2.13~0.2", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-plugin", rpm:"java-1_4_2-sun-plugin~1.4.2.13~0.2", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-src", rpm:"java-1_4_2-sun-src~1.4.2.13~0.2", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESSr8")
{

  if ((res = isrpmvuln(pkg:"java2", rpm:"java2~1.4.2~129.27", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2-jre", rpm:"java2-jre~1.4.2~129.27", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2", rpm:"java2~1.4.2~151", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2-jre", rpm:"java2-jre~1.4.2~151", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2", rpm:"java2~1.3.1~696", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2-jre", rpm:"java2-jre~1.3.1~696", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLPOS9")
{

  if ((res = isrpmvuln(pkg:"java2", rpm:"java2~1.4.2~129.27", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2-jre", rpm:"java2-jre~1.4.2~129.27", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2", rpm:"java2~1.4.2~151", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2-jre", rpm:"java2-jre~1.4.2~151", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2", rpm:"java2~1.3.1~696", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2-jre", rpm:"java2-jre~1.3.1~696", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "OES")
{

  if ((res = isrpmvuln(pkg:"java2", rpm:"java2~1.4.2~129.27", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2-jre", rpm:"java2-jre~1.4.2~129.27", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2", rpm:"java2~1.4.2~151", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2-jre", rpm:"java2-jre~1.4.2~151", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2", rpm:"java2~1.3.1~696", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2-jre", rpm:"java2-jre~1.3.1~696", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES9")
{

  if ((res = isrpmvuln(pkg:"java2", rpm:"java2~1.4.2~129.27", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2-jre", rpm:"java2-jre~1.4.2~129.27", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2", rpm:"java2~1.4.2~151", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2-jre", rpm:"java2-jre~1.4.2~151", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2", rpm:"java2~1.3.1~696", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2-jre", rpm:"java2-jre~1.3.1~696", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9")
{

  if ((res = isrpmvuln(pkg:"java2", rpm:"java2~1.4.2~129.27", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2-jre", rpm:"java2-jre~1.4.2~129.27", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2", rpm:"java2~1.4.2~151", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2-jre", rpm:"java2-jre~1.4.2~151", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2", rpm:"java2~1.3.1~696", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java2-jre", rpm:"java2-jre~1.3.1~696", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun", rpm:"java-1_4_2-sun~1.4.2.13~0.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-alsa", rpm:"java-1_4_2-sun-alsa~1.4.2.13~0.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-demo", rpm:"java-1_4_2-sun-demo~1.4.2.13~0.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-devel", rpm:"java-1_4_2-sun-devel~1.4.2.13~0.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-jdbc", rpm:"java-1_4_2-sun-jdbc~1.4.2.13~0.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-plugin", rpm:"java-1_4_2-sun-plugin~1.4.2.13~0.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-src", rpm:"java-1_4_2-sun-src~1.4.2.13~0.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-sun", rpm:"java-1_5_0-sun~1.5.0_10~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-sun-alsa", rpm:"java-1_5_0-sun-alsa~1.5.0_10~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-sun-demo", rpm:"java-1_5_0-sun-demo~1.5.0_10~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-sun-devel", rpm:"java-1_5_0-sun-devel~1.5.0_10~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-sun-jdbc", rpm:"java-1_5_0-sun-jdbc~1.5.0_10~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-sun-plugin", rpm:"java-1_5_0-sun-plugin~1.5.0_10~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_5_0-sun-src", rpm:"java-1_5_0-sun-src~1.5.0_10~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLED10")
{

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun", rpm:"java-1_4_2-sun~1.4.2.13~0.2", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-alsa", rpm:"java-1_4_2-sun-alsa~1.4.2.13~0.2", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-demo", rpm:"java-1_4_2-sun-demo~1.4.2.13~0.2", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-devel", rpm:"java-1_4_2-sun-devel~1.4.2.13~0.2", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-jdbc", rpm:"java-1_4_2-sun-jdbc~1.4.2.13~0.2", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-plugin", rpm:"java-1_4_2-sun-plugin~1.4.2.13~0.2", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_4_2-sun-src", rpm:"java-1_4_2-sun-src~1.4.2.13~0.2", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
