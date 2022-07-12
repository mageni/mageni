###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for hypervkvpd-0 CESA-2013:0807 centos5
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.881734");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-05-17 09:53:48 +0530 (Fri, 17 May 2013)");
  script_cve_id("CVE-2012-5532");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_name("CentOS Update for hypervkvpd-0 CESA-2013:0807 centos5");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-May/019717.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'hypervkvpd-0'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"hypervkvpd-0 on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The hypervkvpd package contains hypervkvpd, the guest Microsoft Hyper-V
  Key-Value Pair (KVP) daemon. The daemon passes basic information to the
  host through VMBus, such as the guest IP address, fully qualified domain
  name, operating system name, and operating system release number.

  A denial of service flaw was found in the way hypervkvpd processed certain
  Netlink messages. A local, unprivileged user in a guest (running on
  Microsoft Hyper-V) could send a Netlink message that, when processed, would
  cause the guest's hypervkvpd daemon to exit. (CVE-2012-5532)

  The CVE-2012-5532 issue was discovered by Florian Weimer of the Red Hat
  Product Security Team.

  This update also fixes the following bug:

  * The hypervkvpd daemon did not close the file descriptors for pool files
  when they were updated. This could eventually lead to hypervkvpd crashing
  with a 'KVP: Failed to open file, pool: 1' error after consuming all
  available file descriptors. With this update, the file descriptors are
  closed, correcting this issue. (BZ#953502)

  Users of hypervkvpd are advised to upgrade to this updated package, which
  contains backported patches to correct these issues. After installing the
  update, it is recommended to reboot all guest machines.");
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
  ##Changed Package name to hypervkvpd instead hypervkvpd-0
  if ((res = isrpmvuln(pkg:"hypervkvpd", rpm:"hypervkvpd~0~0.7.el5_9.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
