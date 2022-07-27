###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for rdma RHSA-2013:0509-02
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-February/msg00051.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870931");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-02-22 10:02:12 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2012-4517", "CVE-2012-4518");
  script_bugtraq_id(55890);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for rdma RHSA-2013:0509-02");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rdma'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"rdma on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Red Hat Enterprise Linux includes a collection of InfiniBand and iWARP
  utilities, libraries and development packages for writing applications
  that use Remote Direct Memory Access (RDMA) technology.

  A denial of service flaw was found in the way ibacm managed reference
  counts for multicast connections. An attacker could send specially-crafted
  multicast packets that would cause the ibacm daemon to crash.
  (CVE-2012-4517)

  It was found that the ibacm daemon created some files with world-writable
  permissions. A local attacker could use this flaw to overwrite the
  contents of the ibacm.log or ibacm.port file, allowing them to mask
  certain actions from the log or cause ibacm to run on a non-default port.
  (CVE-2012-4518)

  CVE-2012-4518 was discovered by Florian Weimer of the Red Hat Product
  Security Team and Kurt Seifried of the Red Hat Security Response Team.

  The InfiniBand/iWARP/RDMA stack components have been upgraded to more
  recent upstream versions.

  This update also fixes the following bugs:

  * Previously, the ibnodes -h command did not show a proper usage message.
  With this update the problem is fixed and ibnodes -h now shows the
  correct usage message. (BZ#818606)

  * Previously, the ibv_devinfo utility erroneously showed iWARP cxgb3
  hardware's physical state as invalid even when the device was working. For
  iWARP hardware, the phys_state field has no meaning. This update patches
  the utility to not print out anything for this field when the hardware is
  iWARP hardware. (BZ#822781)

  * Prior to the release of Red Hat Enterprise Linux 6.3, the kernel created
  the InfiniBand device files in the wrong place and a udev rules file was
  used to force the devices to be created in the proper place. With the
  update to 6.3, the kernel was fixed to create the InfiniBand device files
  in the proper place, and so the udev rules file was removed as no longer
  being necessary. However, a bug in the kernel device creation meant that,
  although the devices were now being created in the right place, they had
  incorrect permissions. Consequently, when users attempted to run an RDMA
  application as a non-root user, the application failed to get the necessary
  permissions to use the RDMA device and the application terminated. This
  update puts a new udev rules file in place. It no longer attempts to create
  the InfiniBand devices since they already exist, but it does correct the
  device permissions on the ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"ibacm", rpm:"ibacm~1.0.8~0.git7a3adb7.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ibacm-debuginfo", rpm:"ibacm-debuginfo~1.0.8~0.git7a3adb7.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ibsim", rpm:"ibsim~0.5~7.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ibsim-debuginfo", rpm:"ibsim-debuginfo~0.5~7.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ibutils", rpm:"ibutils~1.5.7~7.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ibutils-debuginfo", rpm:"ibutils-debuginfo~1.5.7~7.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ibutils-libs", rpm:"ibutils-libs~1.5.7~7.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"infiniband-diags", rpm:"infiniband-diags~1.5.12~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"infiniband-diags-debuginfo", rpm:"infiniband-diags-debuginfo~1.5.12~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libibmad", rpm:"libibmad~1.3.9~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libibmad-debuginfo", rpm:"libibmad-debuginfo~1.3.9~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libibumad", rpm:"libibumad~1.3.8~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libibumad-debuginfo", rpm:"libibumad-debuginfo~1.3.8~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libibverbs", rpm:"libibverbs~1.1.6~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libibverbs-debuginfo", rpm:"libibverbs-debuginfo~1.1.6~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libibverbs-devel", rpm:"libibverbs-devel~1.1.6~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libibverbs-utils", rpm:"libibverbs-utils~1.1.6~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmlx4", rpm:"libmlx4~1.0.4~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmlx4-debuginfo", rpm:"libmlx4-debuginfo~1.0.4~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librdmacm", rpm:"librdmacm~1.0.17~0.git4b5c1aa.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librdmacm-debuginfo", rpm:"librdmacm-debuginfo~1.0.17~0.git4b5c1aa.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librdmacm-utils", rpm:"librdmacm-utils~1.0.17~0.git4b5c1aa.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opensm", rpm:"opensm~3.3.15~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opensm-debuginfo", rpm:"opensm-debuginfo~3.3.15~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opensm-libs", rpm:"opensm-libs~3.3.15~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rdma", rpm:"rdma~3.6~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"infinipath-psm", rpm:"infinipath-psm~3.0.1~115.1015_open.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"infinipath-psm-debuginfo", rpm:"infinipath-psm-debuginfo~3.0.1~115.1015_open.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libibumad-devel", rpm:"libibumad-devel~1.3.8~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librdmacm-devel", rpm:"librdmacm-devel~1.0.17~0.git4b5c1aa.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
