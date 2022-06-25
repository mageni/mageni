###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for spice-server CESA-2016:1205 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882502");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-06-08 05:22:29 +0200 (Wed, 08 Jun 2016)");
  script_cve_id("CVE-2016-0749", "CVE-2016-2150");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for spice-server CESA-2016:1205 centos7");
  script_tag(name:"summary", value:"Check the version of spice-server");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Simple Protocol for Independent
Computing Environments (SPICE) is a remote display system built for virtual
environments which allows the user to view a computing 'desktop' environment
not only on the machine where it is running, but from anywhere on the Internet
and from a wide variety of machine architectures.

Security Fix(es):

  * A memory allocation flaw, leading to a heap-based buffer overflow, was
found in spice's smartcard interaction, which runs under the QEMU-KVM
context on the host. A user connecting to a guest VM using spice could
potentially use this flaw to crash the QEMU-KVM process or execute
arbitrary code with the privileges of the host's QEMU-KVM process.
(CVE-2016-0749)

  * A memory access flaw was found in the way spice handled certain guests
using crafted primary surface parameters. A user in a guest could use this
flaw to read from and write to arbitrary memory locations on the host.
(CVE-2016-2150)

The CVE-2016-0749 issue was discovered by Jing Zhao (Red Hat) and the
CVE-2016-2150 issue was discovered by Frediano Ziglio (Red Hat).");
  script_tag(name:"affected", value:"spice-server on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-June/021904.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"spice-server", rpm:"spice-server~0.12.4~15.el7_2.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-server-devel", rpm:"spice-server-devel~0.12.4~15.el7_2.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice", rpm:"spice~0.12.4~15.el7_2.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
