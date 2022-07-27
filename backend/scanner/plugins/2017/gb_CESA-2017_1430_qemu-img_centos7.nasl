###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for qemu-img CESA-2017:1430 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882732");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-06-14 06:40:38 +0200 (Wed, 14 Jun 2017)");
  script_cve_id("CVE-2017-7718", "CVE-2017-7980");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for qemu-img CESA-2017:1430 centos7");
  script_tag(name:"summary", value:"Check the version of qemu-img");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Kernel-based Virtual Machine (KVM) is a
full virtualization solution for Linux on a variety of architectures.
The qemu-kvm package provides the user-space component for running virtual
machines that use KVM.

Security Fix(es):

  * An out-of-bounds r/w access issue was found in QEMU's Cirrus CLGD 54xx
VGA Emulator support. The vulnerability could occur while copying VGA data
via various bitblt functions. A privileged user inside a guest could use
this flaw to crash the QEMU process or, potentially, execute arbitrary code
on the host with privileges of the QEMU process. (CVE-2017-7980)

  * An out-of-bounds access issue was found in QEMU's Cirrus CLGD 54xx VGA
Emulator support. The vulnerability could occur while copying VGA data
using bitblt functions (for example, cirrus_bitblt_rop_fwd_transp_). A
privileged user inside a guest could use this flaw to crash the QEMU
process, resulting in denial of service. (CVE-2017-7718)

Red Hat would like to thank Jiangxin (PSIRT Huawei Inc) and Li Qiang (Qihoo
360 Gear Team) for reporting CVE-2017-7980 and Jiangxin (PSIRT Huawei Inc)
for reporting CVE-2017-7718.

Bug Fix(es):

  * Previously, guest virtual machines in some cases became unresponsive when
the 'pty' back end of a serial device performed an irregular I/O
communication. This update improves the handling of serial I/O on guests,
which prevents the described problem from occurring. (BZ#1452332)");
  script_tag(name:"affected", value:"qemu-img on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-June/022458.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~126.el7_3.9", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~126.el7_3.9", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~126.el7_3.9", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~1.5.3~126.el7_3.9", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
