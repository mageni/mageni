###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for python-qpid CESA-2012:1269 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-September/018895.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881503");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-09-22 11:58:03 +0530 (Sat, 22 Sep 2012)");
  script_cve_id("CVE-2012-2145");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("CentOS Update for python-qpid CESA-2012:1269 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-qpid'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"python-qpid on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Apache Qpid is a reliable, cross-platform, asynchronous messaging system
  that supports the Advanced Message Queuing Protocol (AMQP) in several
  common programming languages.

  It was discovered that the Qpid daemon (qpidd) did not allow the number of
  connections from clients to be restricted. A malicious client could use
  this flaw to open an excessive amount of connections, preventing other
  legitimate clients from establishing a connection to qpidd. (CVE-2012-2145)

  To address CVE-2012-2145, new qpidd configuration options were introduced:
  max-negotiate-time defines the time during which initial protocol
  negotiation must succeed, connection-limit-per-user and
  connection-limit-per-ip can be used to limit the number of connections per
  user and client host IP. Refer to the qpidd manual page for additional
  details.

  In addition, the qpid-cpp, qpid-qmf, qpid-tools, and python-qpid packages
  have been upgraded to upstream version 0.14, which provides support for Red
  Hat Enterprise MRG 2.2, as well as a number of bug fixes and enhancements
  over the previous version. (BZ#840053, BZ#840055, BZ#840056, BZ#840058)

  All users of qpid are advised to upgrade to these updated packages, which
  fix these issues and add these enhancements.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"python-qpid", rpm:"python-qpid~0.14~11.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-qpid-qmf", rpm:"python-qpid-qmf~0.14~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qpid-cpp-client", rpm:"qpid-cpp-client~0.14~22.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qpid-cpp-client-devel", rpm:"qpid-cpp-client-devel~0.14~22.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qpid-cpp-client-devel-docs", rpm:"qpid-cpp-client-devel-docs~0.14~22.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qpid-cpp-client-rdma", rpm:"qpid-cpp-client-rdma~0.14~22.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qpid-cpp-client-ssl", rpm:"qpid-cpp-client-ssl~0.14~22.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qpid-cpp-server", rpm:"qpid-cpp-server~0.14~22.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qpid-cpp-server-cluster", rpm:"qpid-cpp-server-cluster~0.14~22.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qpid-cpp-server-devel", rpm:"qpid-cpp-server-devel~0.14~22.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qpid-cpp-server-rdma", rpm:"qpid-cpp-server-rdma~0.14~22.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qpid-cpp-server-ssl", rpm:"qpid-cpp-server-ssl~0.14~22.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qpid-cpp-server-store", rpm:"qpid-cpp-server-store~0.14~22.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qpid-cpp-server-xml", rpm:"qpid-cpp-server-xml~0.14~22.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qpid-qmf", rpm:"qpid-qmf~0.14~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qpid-qmf-devel", rpm:"qpid-qmf-devel~0.14~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qpid-tools", rpm:"qpid-tools~0.14~6.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rh-qpid-cpp-tests", rpm:"rh-qpid-cpp-tests~0.14~22.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-qpid-qmf", rpm:"ruby-qpid-qmf~0.14~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qpid-cpp", rpm:"qpid-cpp~0.14~22.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
