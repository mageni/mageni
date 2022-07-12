###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for expat CESA-2012:0731 centos5
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-June/018682.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881192");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:39:59 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-0876", "CVE-2012-1148");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("CentOS Update for expat CESA-2012:0731 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'expat'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"expat on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Expat is a C library written by James Clark for parsing XML documents.

  A denial of service flaw was found in the implementation of hash arrays in
  Expat. An attacker could use this flaw to make an application using Expat
  consume an excessive amount of CPU time by providing a specially-crafted
  XML file that triggers multiple hash function collisions. To mitigate
  this issue, randomization has been added to the hash function to reduce the
  chance of an attacker successfully causing intentional collisions.
  (CVE-2012-0876)

  A memory leak flaw was found in Expat. If an XML file processed by an
  application linked against Expat triggered a memory re-allocation failure,
  Expat failed to free the previously allocated memory. This could cause the
  application to exit unexpectedly or crash when all available memory is
  exhausted. (CVE-2012-1148)

  All Expat users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the updated
  packages, applications using the Expat library must be restarted for the
  update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"expat", rpm:"expat~1.95.8~11.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"expat-devel", rpm:"expat-devel~1.95.8~11.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
