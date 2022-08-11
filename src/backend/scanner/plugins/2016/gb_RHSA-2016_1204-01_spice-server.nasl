###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for spice-server RHSA-2016:1204-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871628");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-07 05:24:33 +0200 (Tue, 07 Jun 2016)");
  script_cve_id("CVE-2016-0749", "CVE-2016-2150");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for spice-server RHSA-2016:1204-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'spice-server'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Simple Protocol for Independent
Computing Environments (SPICE) is a remote display protocol for virtual environments.
SPICE users can access a virtualized desktop or server from the local system or any
system with network access to the server. SPICE is used in Red Hat Enterprise Linux
for viewing virtualized guests running on the Kernel-based Virtual Machine
(KVM) hypervisor or on Red Hat Enterprise Virtualization Hypervisors.

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
  script_tag(name:"affected", value:"spice-server on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-June/msg00002.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"spice-server", rpm:"spice-server~0.12.4~13.el6.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-server-debuginfo", rpm:"spice-server-debuginfo~0.12.4~13.el6.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
