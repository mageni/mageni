###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for qemu-kvm RHSA-2013:0896-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871005");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-06-04 09:18:31 +0530 (Tue, 04 Jun 2013)");
  script_cve_id("CVE-2013-2007");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for qemu-kvm RHSA-2013:0896-01");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-June/msg00002.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"qemu-kvm on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"KVM (Kernel-based Virtual Machine) is a full virtualization solution for
  Linux on AMD64 and Intel 64 systems. qemu-kvm is the user-space component
  for running virtual machines using KVM.

  It was found that QEMU Guest Agent (the qemu-ga service) created
  certain files with world-writable permissions when run in daemon mode
  (the default mode). An unprivileged guest user could use this flaw to
  consume all free space on the partition containing the qemu-ga log file, or
  modify the contents of the log. When a UNIX domain socket transport was
  explicitly configured to be used (not the default), an unprivileged guest
  user could potentially use this flaw to escalate their privileges in the
  guest. This update requires manual action. Refer below for details.
  (CVE-2013-2007)

  This update does not change the permissions of the existing log file or
  the UNIX domain socket. For these to be changed, stop the qemu-ga service,
  and then manually remove all group and other permissions on the
  affected files, or remove the files.

  Note that after installing this update, files created by the
  guest-file-open QEMU Monitor Protocol (QMP) command will still continue to
  be created with world-writable permissions for backwards compatibility.

  This issue was discovered by Laszlo Ersek of Red Hat.

  This update also fixes the following bugs:

  * Previously, due to integer overflow in code calculations, the qemu-kvm
  utility was reporting incorrect memory size on QMP events when using the
  virtio balloon driver with more than 4 GB of memory. This update fixes the
  overflow in the code and qemu-kvm works as expected in the described
  scenario. (BZ#958750)

  * When the set_link flag is set to off to change the status of a network
  card, the status is changed to down on the respective guest. Previously,
  with certain network cards, when such a guest was restarted, the status of
  the network card was unexpectedly reset to up, even though the network
  was unavailable. A patch has been provided to address this bug and the link
  status change is now preserved across restarts for all network cards.
  (BZ#927591)

  All users of qemu-kvm should upgrade to these updated packages, which
  contain backported patches to correct these issues. After installing this
  update, shut down all running virtual machines. Once all virtual machines
  have shut down, start them again for this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~0.12.1.2~2.355.el6_4.5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-debuginfo", rpm:"qemu-kvm-debuginfo~0.12.1.2~2.355.el6_4.5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.355.el6_4.5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.355.el6_4.5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.355.el6_4.5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
