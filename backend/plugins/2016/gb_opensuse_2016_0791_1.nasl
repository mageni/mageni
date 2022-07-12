###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_0791_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for graphite2 openSUSE-SU-2016:0791-1 (graphite2)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851238");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-03-17 05:11:21 +0100 (Thu, 17 Mar 2016)");
  script_cve_id("CVE-2016-1521", "CVE-2016-1522", "CVE-2016-1523", "CVE-2016-1526");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for graphite2 openSUSE-SU-2016:0791-1 (graphite2)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'graphite2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for graphite2 fixes the following issues:

  - CVE-2016-1521: The directrun function in directmachine.cpp in
  Libgraphite did not validate a certain skip operation, which allowed
  remote attackers to execute arbitrary code, obtain sensitive information,
  or cause a denial of service (out-of-bounds read and application crash)
  via a crafted Graphite smart font.

  - CVE-2016-1522: Code.cpp in Libgraphite did not consider recursive load
  calls during a size check, which allowed remote attackers to cause a
  denial of service (heap-based buffer overflow) or possibly execute
  arbitrary code via a crafted Graphite smart font.

  - CVE-2016-1523: The SillMap::readFace function in FeatureMap.cpp in
  Libgraphite mishandled a return value, which allowed remote attackers to
  cause a denial of service (missing initialization, NULL pointer
  dereference, and application crash) via a crafted Graphite smart font.

  - CVE-2016-1526: The TtfUtil:LocaLookup function in TtfUtil.cpp in
  Libgraphite incorrectly validated a size value, which allowed remote
  attackers to obtain sensitive information or cause a denial of service
  (out-of-bounds read and application crash) via a crafted Graphite smart
  font.");
  script_tag(name:"affected", value:"graphite2 on openSUSE 13.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"graphite2", rpm:"graphite2~1.2.4~2.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"graphite2-debuginfo", rpm:"graphite2-debuginfo~1.2.4~2.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"graphite2-debugsource", rpm:"graphite2-debugsource~1.2.4~2.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"graphite2-devel", rpm:"graphite2-devel~1.2.4~2.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgraphite2-3", rpm:"libgraphite2-3~1.2.4~2.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgraphite2-3-debuginfo", rpm:"libgraphite2-3-debuginfo~1.2.4~2.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgraphite2-3-32bit", rpm:"libgraphite2-3-32bit~1.2.4~2.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgraphite2-3-debuginfo-32bit", rpm:"libgraphite2-3-debuginfo-32bit~1.2.4~2.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
