###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2141_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for linux-ti-omap4 USN-2141-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.841749");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-03-12 09:43:25 +0530 (Wed, 12 Mar 2014)");
  script_cve_id("CVE-2013-4579", "CVE-2013-4587", "CVE-2013-6367", "CVE-2013-6368",
                "CVE-2013-6382", "CVE-2013-7263", "CVE-2013-7264", "CVE-2013-7265",
                "CVE-2013-7266", "CVE-2013-7267", "CVE-2013-7268", "CVE-2013-7269",
                "CVE-2013-7270", "CVE-2013-7271", "CVE-2013-7281", "CVE-2014-1438",
                "CVE-2014-1446", "CVE-2014-1874");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for linux-ti-omap4 USN-2141-1");

  script_tag(name:"affected", value:"linux-ti-omap4 on Ubuntu 13.10");
  script_tag(name:"insight", value:"Mathy Vanhoef discovered an error in the the way the ath9k
driver was handling the BSSID masking. A remote attacker could exploit this
error to discover the original MAC address after a spoofing atack.
(CVE-2013-4579)

Andrew Honig reported a flaw in the Linux Kernel's kvm_vm_ioctl_create_vcpu
function of the Kernel Virtual Machine (KVM) subsystem. A local user could
exploit this flaw to gain privileges on the host machine. (CVE-2013-4587)

Andrew Honig reported a flaw in the apic_get_tmcct function of the Kernel
Virtual Machine (KVM) subsystem if the Linux kernel. A guest OS user could
exploit this flaw to cause a denial of service or host OS system crash.
(CVE-2013-6367)

Andrew Honig reported an error in the Linux Kernel's Kernel Virtual Machine
(KVM) VAPIC synchronization operation. A local user could exploit this flaw
to gain privileges or cause a denial of service (system crash).
(CVE-2013-6368)

Nico Golde and Fabian Yamaguchi reported buffer underflow errors in the
implementation of the XFS filesystem in the Linux kernel. A local user with
CAP_SYS_ADMIN could exploit these flaw to cause a denial of service (memory
corruption) or possibly other unspecified issues. (CVE-2013-6382)

mpd reported an information leak in the recvfrom, recvmmsg, and recvmsg
system calls in the Linux kernel. An unprivileged local user could exploit
this flaw to obtain sensitive information from kernel stack memory.
(CVE-2013-7263)

mpb reported an information leak in the Layer Two Tunneling Protocol (l2tp)
of the Linux kernel. A local user could exploit this flaw to obtain
sensitive information from kernel stack memory. (CVE-2013-7264)

mpb reported an information leak in the Phone Network protocol (phonet) in
the Linux kernel. A local user could exploit this flaw to obtain sensitive
information from kernel stack memory. (CVE-2013-7265)

An information leak was discovered in the recvfrom, recvmmsg, and recvmsg
systemcalls when used with ISDN sockets in the Linux kernel. A local user
could exploit this leak to obtain potentially sensitive information from
kernel memory. (CVE-2013-7266)

An information leak was discovered in the recvfrom, recvmmsg, and recvmsg
systemcalls when used with apple talk sockets in the Linux kernel. A local
user could exploit this leak to obtain potentially sensitive information
from kernel memory. (CVE-2013-7267)

An information leak was discovered in the recvfrom, recvmmsg, and recvmsg
systemcalls when used with ipx protocol sockets in the Linux kernel. A
local user could exploit this leak to obtain potentially sensitive
information from kernel memory. (CVE-2013-7268)

An inf ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2141-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU13\.10");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"linux-image-3.5.0-239-omap4", ver:"3.5.0-239.55", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
