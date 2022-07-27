###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_1043_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for flash-player SUSE-SU-2015:1043-1 (flash-player)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851059");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-16 19:12:27 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2015-3096", "CVE-2015-3098", "CVE-2015-3099", "CVE-2015-3100", "CVE-2015-3102", "CVE-2015-3103", "CVE-2015-3104", "CVE-2015-3105", "CVE-2015-3106", "CVE-2015-3107", "CVE-2015-3108", "CVE-2014-5333");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for flash-player SUSE-SU-2015:1043-1 (flash-player)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following issues are fixed by this updated:

  * CVE-2015-3096: These updates resolve a vulnerability that could be
  exploited to bypass the fix for CVE-2014-5333.

  * CVE-2015-3098, CVE-2015-3099, CVE-2015-3102:These updates resolve
  vulnerabilities that could be exploited to bypass the
  same-origin-policy and lead to information disclosure.

  * CVE-2015-3100: These updates resolve a stack overflow vulnerability
  that could lead to code execution.

  * CVE-2015-3103, CVE-2015-3106, CVE-2015-3107: These updates resolve
  use-after-free vulnerabilities that could lead to code execution.

  * CVE-2015-3104: These updates resolve an integer overflow
  vulnerability that could lead to code execution.

  * CVE-2015-3105: These updates resolve a memory corruption
  vulnerability that could lead to code execution.

  * CVE-2015-3108: These updates resolve a memory leak vulnerability
  that could be used to bypass ASLR (CVE-2015-3108). (bsc#934088)");
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

  if ((res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~11.2.202.466~86.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"flash-player-gnome", rpm:"flash-player-gnome~11.2.202.466~86.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
