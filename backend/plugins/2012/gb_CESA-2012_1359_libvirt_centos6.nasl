###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libvirt CESA-2012:1359 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-October/018933.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881516");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-10-12 09:20:09 +0530 (Fri, 12 Oct 2012)");
  script_cve_id("CVE-2012-4423");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("CentOS Update for libvirt CESA-2012:1359 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"libvirt on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The libvirt library is a C API for managing and interacting with the
  virtualization capabilities of Linux and other operating systems. In
  addition, libvirt provides tools for remote management of virtualized
  systems.

  A flaw was found in libvirtd's RPC call handling. An attacker able to
  establish a read-only connection to libvirtd could use this flaw to crash
  libvirtd by sending an RPC message that has an event as the RPC number, or
  an RPC number that falls into a gap in the RPC dispatch table.
  (CVE-2012-4423)

  This issue was discovered by Wenlong Huang of the Red Hat Virtualization QE
  Team.

  This update also fixes the following bugs:

  * When the host_uuid option was present in the libvirtd.conf file, the
  augeas libvirt lens was unable to parse the file. This bug has been fixed
  and the augeas libvirt lens now parses libvirtd.conf as expected in the
  described scenario. (BZ#858988)

  * Disk hot plug is a two-part action: the qemuMonitorAddDrive() call is
  followed by the qemuMonitorAddDevice() call. When the first part succeeded
  but the second one failed, libvirt failed to roll back the first part and
  the device remained in use even though the disk hot plug failed. With this
  update, the rollback for the drive addition is properly performed in the
  described scenario and disk hot plug now works as expected. (BZ#859376)

  * When a virtual machine was started with an image chain using block
  devices and a block rebase operation was issued, the operation failed on
  completion in the blockJobAbort() function. This update relabels and
  configures cgroups for the backing files and the rebase operation now
  succeeds. (BZ#860720)

  All users of libvirt are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues. After installing
  the updated packages, libvirtd will be restarted automatically.");
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

  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.9.10~21.el6_3.5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~0.9.10~21.el6_3.5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.9.10~21.el6_3.5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.9.10~21.el6_3.5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~0.9.10~21.el6_3.5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
