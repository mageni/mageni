###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_1319_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for java-1_7_0-openjdk SUSE-SU-2015:1319-1 (java-1_7_0-openjdk)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850898");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-16 13:39:54 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2015-2590", "CVE-2015-2596", "CVE-2015-2597", "CVE-2015-2601",
                "CVE-2015-2613", "CVE-2015-2619", "CVE-2015-2621", "CVE-2015-2625",
                "CVE-2015-2627", "CVE-2015-2628", "CVE-2015-2632", "CVE-2015-2637",
                "CVE-2015-2638", "CVE-2015-2664", "CVE-2015-2808", "CVE-2015-4000",
                "CVE-2015-4729", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733",
                "CVE-2015-4736", "CVE-2015-4748", "CVE-2015-4749", "CVE-2015-4760");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for java-1_7_0-openjdk SUSE-SU-2015:1319-1 (java-1_7_0-openjdk)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-openjdk'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenJDK was updated to 2.6.1 - OpenJDK 7u85 to fix security issues and
  bugs.

  The following vulnerabilities were fixed:

  * CVE-2015-2590: Easily exploitable vulnerability in the Libraries
  component allowed successful unauthenticated network attacks via
  multiple protocols. Successful attack of this vulnerability could have
  resulted in unauthorized Operating System takeover including arbitrary
  code execution.

  * CVE-2015-2596: Difficult to exploit vulnerability in the Hotspot
  component allowed successful unauthenticated network attacks via
  multiple protocols. Successful attack of this vulnerability could have
  resulted in unauthorized update, insert or delete access to some Java
  accessible data.

  * CVE-2015-2597: Easily exploitable vulnerability in the Install component
  requiring logon to Operating System. Successful attack of this
  vulnerability could have resulted in unauthorized Operating System
  takeover including arbitrary code execution.

  * CVE-2015-2601: Easily exploitable vulnerability in the JCE component
  allowed successful unauthenticated network attacks via multiple
  protocols. Successful attack of this vulnerability could have resulted
  in unauthorized read access to a subset of Java accessible data.

  * CVE-2015-2613: Easily exploitable vulnerability in the JCE component
  allowed successful unauthenticated network attacks via multiple
  protocols. Successful attack of this vulnerability could have resulted
  in unauthorized read access to a subset of Java SE, Java SE Embedded
  accessible data.

  * CVE-2015-2619: Easily exploitable vulnerability in the 2D component
  allowed successful unauthenticated network attacks via multiple
  protocols. Successful attack of this vulnerability could have resulted
  in unauthorized read access to a subset of Java accessible data.

  * CVE-2015-2621: Easily exploitable vulnerability in the JMX component
  allowed successful unauthenticated network attacks via multiple
  protocols. Successful attack of this vulnerability could have resulted
  in unauthorized read access to a subset of Java accessible data.

  * CVE-2015-2625: Very difficult to exploit vulnerability in the JSSE
  component allowed successful unauthenticated network attacks via
  SSL/TLS. Successful attack of this vulnerability could have resulted in
  unauthorized read access to a subset of Java accessible data.

  * CVE-2015-2627: Very difficult to exploit vulnerability in the Install
  component allowed successful unauthenticated network attacks via
  multiple protocols. Successful a ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"java-1_7_0-openjdk on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(SLED12\.0SP0|SLES12\.0SP0)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLED12.0SP0")
{

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.85~18.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-debuginfo", rpm:"java-1_7_0-openjdk-debuginfo~1.7.0.85~18.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-debugsource", rpm:"java-1_7_0-openjdk-debugsource~1.7.0.85~18.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.85~18.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless-debuginfo", rpm:"java-1_7_0-openjdk-headless-debuginfo~1.7.0.85~18.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "SLES12.0SP0")
{

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.85~18.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-debuginfo", rpm:"java-1_7_0-openjdk-debuginfo~1.7.0.85~18.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-debugsource", rpm:"java-1_7_0-openjdk-debugsource~1.7.0.85~18.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.85~18.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo-debuginfo", rpm:"java-1_7_0-openjdk-demo-debuginfo~1.7.0.85~18.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.85~18.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel-debuginfo", rpm:"java-1_7_0-openjdk-devel-debuginfo~1.7.0.85~18.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.85~18.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless-debuginfo", rpm:"java-1_7_0-openjdk-headless-debuginfo~1.7.0.85~18.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
