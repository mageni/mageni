###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for RDMA stack RHSA-2013:1661-02
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871080");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-11-21 10:44:13 +0530 (Thu, 21 Nov 2013)");
  script_cve_id("CVE-2012-4516", "CVE-2013-2561");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:C/A:C");
  script_name("RedHat Update for RDMA stack RHSA-2013:1661-02");


  script_tag(name:"affected", value:"RDMA stack on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"insight", value:"Red Hat Enterprise Linux includes a collection of Infiniband and iWARP
utilities, libraries and development packages for writing applications that
use Remote Direct Memory Access (RDMA) technology.

A flaw was found in the way ibutils handled temporary files. A local
attacker could use this flaw to cause arbitrary files to be overwritten as
the root user via a symbolic link attack. (CVE-2013-2561)

It was discovered that librdmacm used a static port to connect to the
ib_acm service. A local attacker able to run a specially crafted ib_acm
service on that port could use this flaw to provide incorrect address
resolution information to librmdacm applications. (CVE-2012-4516)

The CVE-2012-4516 issue was discovered by Florian Weimer of the Red Hat
Product Security Team.

This advisory updates the following packages to the latest upstream
releases, providing a number of bug fixes and enhancements over the
previous versions:

  * libibverbs-1.1.7

  * libmlx4-1.0.5

  * librdmacm-1.0.17

  * mstflint-3.0

  * perftest-2.0

  * qperf-0.4.9

  * rdma-3.10

Several bugs have been fixed in the openmpi, mpitests, ibutils, and
infinipath-psm packages.

The most notable changes in these updated packages from the RDMA stack are
the following:

  * Multiple bugs in the Message Passing Interface (MPI) test packages were
resolved, allowing more of the mpitest applications to pass on the
underlying MPI implementations.

  * The libmlx4 package now includes dracut module files to ensure that any
necessary custom configuration of mlx4 port types is included in the
initramfs dracut builds.

  * Multiple test programs in the perftest and qperf packages now work
properly over RoCE interfaces, or when specifying the use of rdmacm
queue pairs.

  * The mstflint package has been updated to the latest upstream version,
which is now capable of burning firmware on newly released Mellanox
Connect-IB hardware.

  * A compatibility problem between the openmpi and infinipath-psm packages
has been resolved with new builds of these packages.

All RDMA users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add
these enhancements.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-November/msg00032.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'RDMA stack'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"ibutils", rpm:"ibutils~1.5.7~8.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ibutils-debuginfo", rpm:"ibutils-debuginfo~1.5.7~8.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ibutils-libs", rpm:"ibutils-libs~1.5.7~8.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libibverbs", rpm:"libibverbs~1.1.7~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libibverbs-debuginfo", rpm:"libibverbs-debuginfo~1.1.7~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libibverbs-devel", rpm:"libibverbs-devel~1.1.7~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libibverbs-utils", rpm:"libibverbs-utils~1.1.7~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmlx4", rpm:"libmlx4~1.0.5~4.el6.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmlx4-debuginfo", rpm:"libmlx4-debuginfo~1.0.5~4.el6.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librdmacm", rpm:"librdmacm~1.0.17~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librdmacm-debuginfo", rpm:"librdmacm-debuginfo~1.0.17~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librdmacm-utils", rpm:"librdmacm-utils~1.0.17~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mpitests-debuginfo", rpm:"mpitests-debuginfo~3.2~9.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mpitests-mvapich", rpm:"mpitests-mvapich~3.2~9.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mpitests-mvapich2", rpm:"mpitests-mvapich2~3.2~9.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mpitests-openmpi", rpm:"mpitests-openmpi~3.2~9.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mstflint", rpm:"mstflint~3.0~0.6.g6961daa.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mstflint-debuginfo", rpm:"mstflint-debuginfo~3.0~0.6.g6961daa.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openmpi", rpm:"openmpi~1.5.4~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openmpi-debuginfo", rpm:"openmpi-debuginfo~1.5.4~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openmpi-devel", rpm:"openmpi-devel~1.5.4~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perftest", rpm:"perftest~2.0~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perftest-debuginfo", rpm:"perftest-debuginfo~2.0~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qperf", rpm:"qperf~0.4.9~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qperf-debuginfo", rpm:"qperf-debuginfo~0.4.9~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rdma", rpm:"rdma~3.10~3.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"infinipath-psm", rpm:"infinipath-psm~3.0.1~115.1015_open.2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"infinipath-psm-debuginfo", rpm:"infinipath-psm-debuginfo~3.0.1~115.1015_open.2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librdmacm-devel", rpm:"librdmacm-devel~1.0.17~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
