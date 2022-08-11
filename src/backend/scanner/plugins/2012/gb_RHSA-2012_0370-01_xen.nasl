###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for xen RHSA-2012:0370-01
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-March/msg00006.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870573");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-03-09 10:25:35 +0530 (Fri, 09 Mar 2012)");
  script_cve_id("CVE-2012-0029");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_name("RedHat Update for xen RHSA-2012:0370-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"xen on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The xen packages contain administration tools and the xend service for
  managing the kernel-xen kernel for virtualization on Red Hat Enterprise
  Linux.

  A heap overflow flaw was found in the way QEMU emulated the e1000 network
  interface card. A privileged guest user in a virtual machine whose network
  interface is configured to use the e1000 emulated driver could use this
  flaw to crash QEMU or, possibly, escalate their privileges on the host.
  (CVE-2012-0029)

  Red Hat would like to thank Nicolae Mogoreanu for reporting this issue.

  This update also fixes the following bugs:

  * Adding support for jumbo frames introduced incorrect network device
  expansion when a bridge is created. The expansion worked correctly with the
  default configuration, but could have caused network setup failures when a
  user-defined network script was used. This update changes the expansion so
  network setup will not fail, even when a user-defined network script is
  used. (BZ#797191)

  * A bug was found in xenconsoled, the Xen hypervisor console daemon. If
  timestamp logging for this daemon was enabled (using both the
  XENCONSOLED_TIMESTAMP_HYPERVISOR_LOG and XENCONSOLED_TIMESTAMP_GUEST_LOG
  options in '/etc/sysconfig/xend'), xenconsoled could crash if the guest
  emitted a lot of information to its serial console in a short period of
  time. Eventually, the guest would freeze after the console buffer was
  filled due to the crashed xenconsoled. Timestamp logging is disabled by
  default. (BZ#797836)

  All xen users are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. The system must be
  rebooted for this update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"xen-debuginfo", rpm:"xen-debuginfo~3.0.3~135.el5_8.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~3.0.3~135.el5_8.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
