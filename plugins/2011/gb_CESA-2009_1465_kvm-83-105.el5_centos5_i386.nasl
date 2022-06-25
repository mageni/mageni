# Copyright (C) 2011 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-October/016238.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880812");
  script_version("2021-04-19T11:57:41+0000");
  script_tag(name:"last_modification", value:"2021-04-20 10:28:26 +0000 (Tue, 20 Apr 2021)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2009:1465");
  script_cve_id("CVE-2009-3290");
  script_name("CentOS Update for kvm-83-105.el5_ CESA-2009:1465 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm-83-105.el5_'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"kvm-83-105.el5_ on CentOS 5");
  script_tag(name:"insight", value:"KVM (Kernel-based Virtual Machine) is a full virtualization solution for
  Linux on AMD64 and Intel 64 systems. KVM is a Linux kernel module built for
  the standard Red Hat Enterprise Linux kernel.

  The kvm_emulate_hypercall() implementation was missing a check for the
  Current Privilege Level (CPL). A local, unprivileged user in a virtual
  machine could use this flaw to cause a local denial of service or escalate
  their privileges within that virtual machine. (CVE-2009-3290)

  This update also fixes the following bugs:

  * non-maskable interrupts (NMI) were not supported on systems with AMD
  processors. As a consequence, Windows Server 2008 R2 guests running with
  more than one virtual CPU assigned on systems with AMD processors would
  hang at the Windows shut down screen when a restart was attempted. This
  update adds support for NMI filtering on systems with AMD processors,
  allowing clean restarts of Windows Server 2008 R2 guests running with
  multiple virtual CPUs. (BZ#520694)

  * significant performance issues for guests running 64-bit editions of
  Windows. This update improves performance for guests running 64-bit
  editions of Windows. (BZ#521793)

  * Windows guests may have experienced time drift. (BZ#521794)

  * removing the Red Hat VirtIO Ethernet Adapter from a guest running Windows
  Server 2008 R2 caused KVM to crash. With this update, device removal should
  not cause this issue. (BZ#524557)

  All KVM users should upgrade to these updated packages, which contain
  backported patches to resolve these issues. Note: The procedure in the
  Solution section must be performed before this update takes effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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
report = "";

if(release == "CentOS5") {
  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~105.el5_4.7", rls:"CentOS5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
