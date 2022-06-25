###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for xorg-x11-drv-qxl CESA-2013:0218 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-February/019222.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881590");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-02-04 09:55:22 +0530 (Mon, 04 Feb 2013)");
  script_cve_id("CVE-2013-0241");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_name("CentOS Update for xorg-x11-drv-qxl CESA-2013:0218 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-drv-qxl'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"xorg-x11-drv-qxl on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The xorg-x11-drv-qxl package provides an X11 video driver for the QEMU QXL
  video accelerator. This driver makes it possible to use Red Hat Enterprise
  Linux 6 as a guest operating system under the KVM kernel module and the
  QEMU multi-platform emulator, using the SPICE protocol.

  A flaw was found in the way the host's qemu-kvm qxl driver and the guest's
  X.Org qxl driver interacted when a SPICE connection terminated. A user able
  to initiate a SPICE connection to a guest could use this flaw to make the
  guest temporarily unavailable or, potentially (if the sysctl
  kernel.softlockup_panic variable was set to '1' in the guest), crash the
  guest. (CVE-2013-0241)

  All users of xorg-x11-drv-qxl are advised to upgrade to this updated
  package, which contains a backported patch to correct this issue. All
  running X.Org server instances using the qxl driver must be restarted for
  this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"xorg-x11-drv-qxl", rpm:"xorg-x11-drv-qxl~0.0.14~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
