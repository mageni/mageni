###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0722_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for Adobe SUSE-SU-2015:0722-1 (Adobe)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851029");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-16 18:00:29 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2015-0346", "CVE-2015-0347", "CVE-2015-0348", "CVE-2015-0349", "CVE-2015-0350", "CVE-2015-0351", "CVE-2015-0352", "CVE-2015-0353", "CVE-2015-0354", "CVE-2015-0355", "CVE-2015-0356", "CVE-2015-0357", "CVE-2015-0358", "CVE-2015-0359", "CVE-2015-0360", "CVE-2015-3038", "CVE-2015-3039", "CVE-2015-3040", "CVE-2015-3041", "CVE-2015-3042", "CVE-2015-3043", "CVE-2015-3044");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for Adobe SUSE-SU-2015:0722-1 (Adobe)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'Adobe'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Adobe Flash Player was updated to 11.2.202.457 to fix several security
  issues that could lead to remote code execution.

  An exploit for CVE-2015-3043 was reported to exist in the wild.

  The following vulnerabilities were fixed:

  * Memory corruption vulnerabilities that could lead to code execution
  (CVE-2015-0347, CVE-2015-0350, CVE-2015-0352, CVE-2015-0353,
  CVE-2015-0354, CVE-2015-0355, CVE-2015-0360, CVE-2015-3038,
  CVE-2015-3041, CVE-2015-3042, CVE-2015-3043).

  * Type confusion vulnerability that could lead to code execution
  (CVE-2015-0356).

  * Buffer overflow vulnerability that could lead to code execution
  (CVE-2015-0348).

  * Use-after-free vulnerabilities that could lead to code execution
  (CVE-2015-0349, CVE-2015-0351, CVE-2015-0358, CVE-2015-3039).

  * Double-free vulnerabilities that could lead to code execution
  (CVE-2015-0346, CVE-2015-0359).

  * Memory leak vulnerabilities that could be used to bypass ASLR
  (CVE-2015-0357, CVE-2015-3040).

  * Security bypass vulnerability that could lead to information disclosure
  (CVE-2015-3044).");
  script_tag(name:"affected", value:"Adobe on SUSE Linux Enterprise Desktop 12");
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

  if ((res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~11.2.202.457~80.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"flash-player-gnome", rpm:"flash-player-gnome~11.2.202.457~80.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
