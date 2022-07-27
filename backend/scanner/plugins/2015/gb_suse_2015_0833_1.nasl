###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0833_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for java-1_7_0-openjdk SUSE-SU-2015:0833-1 (java-1_7_0-openjdk)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850987");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-16 16:14:19 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2015-0458", "CVE-2015-0459", "CVE-2015-0460", "CVE-2015-0469", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0484", "CVE-2015-0488", "CVE-2015-0491", "CVE-2015-0492");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for java-1_7_0-openjdk SUSE-SU-2015:0833-1 (java-1_7_0-openjdk)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-openjdk'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenJDK was updated to version 2.5.5 - OpenJDK 7u79 to fix security issues
  and bugs.

  The following vulnerabilities have been fixed:

  * CVE-2015-0458: Deployment: unauthenticated remote attackers could
  execute arbitrary code via multiple protocols.

  * CVE-2015-0459: 2D: unauthenticated remote attackers could execute
  arbitrary code via multiple protocols.

  * CVE-2015-0460: Hotspot: unauthenticated remote attackers could
  execute arbitrary code via multiple protocols.

  * CVE-2015-0469: 2D: unauthenticated remote attackers could execute
  arbitrary code via multiple protocols.

  * CVE-2015-0477: Beans: unauthenticated remote attackers could update,
  insert or delete some JAVA accessible data via multiple protocols

  * CVE-2015-0478: JCE: unauthenticated remote attackers could read some
  JAVA accessible data via multiple protocols

  * CVE-2015-0480: Tools: unauthenticated remote attackers could update,
  insert or delete some JAVA accessible data via multiple protocols
  and cause a partial denial of service (partial DOS)

  * CVE-2015-0484: JavaFX: unauthenticated remote attackers could read,
  update, insert or delete access some Java accessible data via
  multiple protocols and cause a partial denial of service (partial
  DOS).

  * CVE-2015-0488: JSSE: unauthenticated remote attackers could cause a
  partial denial of service (partial DOS).

  * CVE-2015-0491: 2D: unauthenticated remote attackers could execute
  arbitrary code via multiple protocols.

  * CVE-2015-0492: JavaFX: unauthenticated remote attackers could
  execute arbitrary code via multiple protocols.");

  script_tag(name:"affected", value:"java-1_7_0-openjdk on SUSE Linux Enterprise Desktop 11 SP3");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLED11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLED11.0SP3")
{

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.75~0.9.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.75~0.9.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.75~0.9.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}