###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_2401_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for flash-player SUSE-SU-2015:2401-1 (flash-player)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851152");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-12-31 05:12:51 +0100 (Thu, 31 Dec 2015)");
  script_cve_id("CVE-2015-8459", "CVE-2015-8460", "CVE-2015-8634", "CVE-2015-8635",
                "CVE-2015-8636", "CVE-2015-8638", "CVE-2015-8639", "CVE-2015-8640",
                "CVE-2015-8641", "CVE-2015-8642", "CVE-2015-8643", "CVE-2015-8644",
                "CVE-2015-8645", "CVE-2015-8646", "CVE-2015-8647", "CVE-2015-8648",
                "CVE-2015-8649", "CVE-2015-8650", "CVE-2015-8651");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for flash-player SUSE-SU-2015:2401-1 (flash-player)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for flash-player fixes the following issues:

  - CVE-2015-8644: Type confusion vulnerability that could lead to code
  execution .

  - CVE-2015-8651: Integer overflow vulnerability that could lead to code
  execution.

  - CVE-2015-8634, CVE-2015-8635, CVE-2015-8638, CVE-2015-8639,
  CVE-2015-8640, CVE-2015-8641, CVE-2015-8642, CVE-2015-8643,
  CVE-2015-8646, CVE-2015-8647, CVE-2015-8648, CVE-2015-8649,
  CVE-2015-8650: Use-after-free vulnerabilities that could lead to code
  execution.

  - CVE-2015-8459, CVE-2015-8460, CVE-2015-8636, CVE-2015-8645: Memory
  corruption vulnerabilities that could lead to code execution.");
  script_tag(name:"affected", value:"flash-player on SUSE Linux Enterprise Desktop 12");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLED12\.0SP0");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLED12.0SP0")
{

  if ((res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~11.2.202.559~117.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"flash-player-gnome", rpm:"flash-player-gnome~11.2.202.559~117.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
