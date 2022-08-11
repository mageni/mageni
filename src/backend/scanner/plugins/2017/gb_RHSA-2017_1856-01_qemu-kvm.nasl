###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_1856-01_qemu-kvm.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# RedHat Update for qemu-kvm RHSA-2017:1856-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871866");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-08-04 12:46:53 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2016-4020", "CVE-2017-2633", "CVE-2017-5898");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for qemu-kvm RHSA-2017:1856-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Kernel-based Virtual Machine (KVM) is a full
  virtualization solution for Linux on a variety of architectures. The qemu-kvm
  package provides the user-space component for running virtual machines that use
  KVM. Security Fix(es): * An out-of-bounds memory access issue was found in Quick
  Emulator (QEMU) in the VNC display driver. This flaw could occur while
  refreshing the VNC display surface area in the 'vnc_refresh_server_surface'. A
  user inside a guest could use this flaw to crash the QEMU process.
  (CVE-2017-2633) * An integer overflow flaw was found in Quick Emulator (QEMU) in
  the CCID Card device support. The flaw could occur while passing messages via
  command/response packets to and from the host. A privileged user inside a guest
  could use this flaw to crash the QEMU process. (CVE-2017-5898) * An information
  exposure flaw was found in Quick Emulator (QEMU) in Task Priority Register (TPR)
  optimizations for 32-bit Windows guests. The flaw could occur while accessing
  TPR. A privileged user inside a guest could use this issue to read portions of
  the host memory. (CVE-2016-4020) Red Hat would like to thank Li Qiang (360.cn
  Inc.) for reporting CVE-2017-5898 and Donghai Zdh (Alibaba Inc.) for reporting
  CVE-2016-4020. Additional Changes: For detailed information on changes in this
  release, see the Red Hat Enterprise Linux 7.4 Release Notes linked from the
  References section.");
  script_tag(name:"affected", value:"qemu-kvm on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-August/msg00010.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~141.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~141.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~141.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-debuginfo", rpm:"qemu-kvm-debuginfo~1.5.3~141.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~1.5.3~141.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}