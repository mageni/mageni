###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libvirt CESA-2010:0615 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-August/016896.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880654");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:N/A:N");
  script_cve_id("CVE-2010-2239", "CVE-2010-2242");
  script_name("CentOS Update for libvirt CESA-2010:0615 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"libvirt on CentOS 5");
  script_tag(name:"insight", value:"The libvirt library is a C API for managing and interacting with the
  virtualization capabilities of Linux and other operating systems. In
  addition, libvirt provides tools for remotely managing virtualized systems.

  It was found that libvirt did not set the user-defined backing store format
  when creating a new image, possibly resulting in applications having to
  probe the backing store to discover the format. A privileged guest user
  could use this flaw to read arbitrary files on the host. (CVE-2010-2239)

  It was found that libvirt created insecure iptables rules on the host when
  a guest system was configured for IP masquerading, allowing the guest to
  use privileged ports on the host when accessing network resources. A
  privileged guest user could use this flaw to access network resources that
  would otherwise not be accessible to the guest. (CVE-2010-2242)

  Red Hat would like to thank Jeremy Nickurak for reporting the CVE-2010-2242
  issue.

  This update also fixes the following bugs:

  * a Linux software bridge assumes the MAC address of the enslaved interface
  with the numerically lowest MAC address. When the bridge changes its MAC
  address, for a period of time it does not relay packets across network
  segments, resulting in a temporary network 'blackout'. The bridge should
  thus avoid changing its MAC address in order not to disrupt network
  communications.

  The Linux kernel assigns network TAP devices a random MAC address.
  Occasionally, this random MAC address is lower than that of the physical
  interface which is enslaved (for example, eth0 or eth1), which causes the
  bridge to change its MAC address, thereby disrupting network communications
  for a period of time.

  With this update, libvirt now sets an explicit MAC address for all TAP
  devices created using the configured MAC address from the XML, but with the
  high bit set to 0xFE. The result is that TAP device MAC addresses are now
  numerically greater than those for physical interfaces, and bridges should
  no longer attempt to switch their MAC address to that of the TAP device,
  thus avoiding potential spurious network disruptions. (BZ#617243)

  * a memory leak in the libvirt driver for the Xen hypervisor has been fixed
  with this update. (BZ#619711)

  * the xm and virsh management user interfaces for virtual guests can be
  called on the command line to list the number of active guests. However,
  under certain circumstances, running the 'virsh list' command resulted in
  virsh not listing all of the virtual guests that were active (that is,
  running)  ...

  Description truncated, please see the referenced URL(s) for more information.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.6.3~33.el5_5.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.6.3~33.el5_5.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.6.3~33.el5_5.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
