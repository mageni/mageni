###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_1874_2.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for java-1_7_0-openjdk SUSE-SU-2015:1874-2 (java-1_7_0-openjdk)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851122");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-11-03 06:07:41 +0100 (Tue, 03 Nov 2015)");
  script_cve_id("CVE-2015-4734", "CVE-2015-4803", "CVE-2015-4805", "CVE-2015-4806",
                "CVE-2015-4835", "CVE-2015-4840", "CVE-2015-4842", "CVE-2015-4843",
                "CVE-2015-4844", "CVE-2015-4860", "CVE-2015-4872", "CVE-2015-4881",
                "CVE-2015-4882", "CVE-2015-4883", "CVE-2015-4893", "CVE-2015-4903",
                "CVE-2015-4911");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for java-1_7_0-openjdk SUSE-SU-2015:1874-2 (java-1_7_0-openjdk)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-openjdk'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"java-1_7_0-openjdk was updated to version 7u91 to fix 17 security issues.

  These security issues were fixed:

  - CVE-2015-4843: Unspecified vulnerability in Oracle Java SE 6u101, 7u85,
  and 8u60, and Java SE Embedded 8u51, allowed remote attackers to affect
  confidentiality, integrity, and availability via unknown vectors related
  to Libraries (bsc#951376).

  - CVE-2015-4842: Unspecified vulnerability in Oracle Java SE 6u101, 7u85,
  and 8u60, and Java SE Embedded 8u51, allowed remote attackers to affect
  confidentiality via vectors related to JAXP (bsc#951376).

  - CVE-2015-4840: Unspecified vulnerability in Oracle Java SE 7u85 and
  8u60, and Java SE Embedded 8u51, allowed remote attackers to affect
  confidentiality via unknown vectors related to 2D (bsc#951376).

  - CVE-2015-4872: Unspecified vulnerability in Oracle Java SE 6u101, 7u85,
  and 8u60  Java SE Embedded 8u51  and JRockit R28.3.7 allowed remote
  attackers to affect integrity via unknown vectors related to Security
  (bsc#951376).

  - CVE-2015-4860: Unspecified vulnerability in Oracle Java SE 6u101, 7u85,
  and 8u60, and Java SE Embedded 8u51, allowed remote attackers to affect
  confidentiality, integrity, and availability via vectors related to RMI,
  a different vulnerability than CVE-2015-4883 (bsc#951376).

  - CVE-2015-4844: Unspecified vulnerability in Oracle Java SE 6u101, 7u85,
  and 8u60, and Java SE Embedded 8u51, allowed remote attackers to affect
  confidentiality, integrity, and availability via unknown vectors related
  to 2D (bsc#951376).

  - CVE-2015-4883: Unspecified vulnerability in Oracle Java SE 6u101, 7u85,
  and 8u60, and Java SE Embedded 8u51, allowed remote attackers to affect
  confidentiality, integrity, and availability via vectors related to RMI,
  a different vulnerability than CVE-2015-4860 (bsc#951376).

  - CVE-2015-4893: Unspecified vulnerability in Oracle Java SE 6u101, 7u85,
  and 8u60  Java SE Embedded 8u51  and JRockit R28.3.7 allowed remote
  attackers to affect availability via vectors related to JAXP, a
  different vulnerability than CVE-2015-4803 and CVE-2015-4911
  (bsc#951376).

  - CVE-2015-4911: Unspecified vulnerability in Oracle Java SE 6u101, 7u85,
  and 8u60  Java SE Embedded 8u51  and JRockit R28.3.7 allowed remote
  attackers to affect availability via vectors related to JAXP, a
  different vulnerability than CVE-2015-4803 and CVE-2015-4893
  (bsc#951376).

  - CVE-2015-4882: Unspecified vulnerability in Oracle Java SE 6u101, 7u85,
  and 8u60, and Java SE Embedded 8u51, allowed remote attackers to affect
  av ...

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

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.91~21.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-debuginfo", rpm:"java-1_7_0-openjdk-debuginfo~1.7.0.91~21.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-debugsource", rpm:"java-1_7_0-openjdk-debugsource~1.7.0.91~21.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.91~21.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless-debuginfo", rpm:"java-1_7_0-openjdk-headless-debuginfo~1.7.0.91~21.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "SLES12.0SP0")
{

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.91~21.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-debuginfo", rpm:"java-1_7_0-openjdk-debuginfo~1.7.0.91~21.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-debugsource", rpm:"java-1_7_0-openjdk-debugsource~1.7.0.91~21.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.91~21.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo-debuginfo", rpm:"java-1_7_0-openjdk-demo-debuginfo~1.7.0.91~21.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.91~21.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel-debuginfo", rpm:"java-1_7_0-openjdk-devel-debuginfo~1.7.0.91~21.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.91~21.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless-debuginfo", rpm:"java-1_7_0-openjdk-headless-debuginfo~1.7.0.91~21.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
