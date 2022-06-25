###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for xen RHSA-2011:1401-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-October/msg00017.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870508");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2011-10-31 13:45:00 +0100 (Mon, 31 Oct 2011)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2011-3346");
  script_name("RedHat Update for xen RHSA-2011:1401-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"xen on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The xen packages contain administration tools and the xend service for
  managing the kernel-xen kernel for virtualization on Red Hat Enterprise
  Linux.

  A buffer overflow flaw was found in the Xen hypervisor SCSI subsystem
  emulation. An unprivileged, local guest user could provide a large number
  of bytes that are used to zero out a fixed-sized buffer via a SAI READ
  CAPACITY SCSI command, overwriting memory and causing the guest to crash.
  (CVE-2011-3346)

  This update also fixes the following bugs:

  * Prior to this update, the vif-bridge script used a maximum transmission
  unit (MTU) of 1500 for a new Virtual Interface (VIF). As a result, the MTU
  of the VIF could differ from that of the target bridge. This update fixes
  the VIF hot-plug script so that the default MTU for new VIFs will match
  that of the target Xen hypervisor bridge. In combination with a new enough
  kernel (RHSA-2011:1386), this enables the use of jumbo frames in Xen
  hypervisor guests. (BZ#738608)

  * Prior to this update, the network-bridge script set the MTU of the bridge
  to 1500. As a result, the MTU of the Xen hypervisor bridge could differ
  from that of the physical interface. This update fixes the network script
  so the MTU of the bridge can be set higher than 1500, thus also providing
  support for jumbo frames. Now, the MTU of the Xen hypervisor bridge will
  match that of the physical interface. (BZ#738610)

  * Red Hat Enterprise Linux 5.6 introduced an optimized migration handling
  that speeds up the migration of guests with large memory. However, the new
  migration procedure can theoretically cause data corruption. While no cases
  were observed in practice, with this update, the xend daemon properly waits
  for correct device release before the guest is started on a destination
  machine, thus fixing this bug. (BZ#743850)

  Note: Before a guest is using a new enough kernel (RHSA-2011:1386), the MTU
  of the VIF will drop back to 1500 (if it was set higher) after migration.

  All xen users are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. After installing the
  updated packages, the xend service must be restarted for this update to
  take effect.");
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

  if ((res = isrpmvuln(pkg:"xen-debuginfo", rpm:"xen-debuginfo~3.0.3~132.el5_7.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~3.0.3~132.el5_7.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
