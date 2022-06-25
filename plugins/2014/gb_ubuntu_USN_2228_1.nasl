###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2228_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for linux USN-2228-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841832");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-06-02 14:33:19 +0530 (Mon, 02 Jun 2014)");
  script_cve_id("CVE-2014-1738", "CVE-2014-1737", "CVE-2014-0055", "CVE-2014-0077",
                "CVE-2014-0100", "CVE-2014-0101", "CVE-2014-2309", "CVE-2014-2523",
                "CVE-2014-2672", "CVE-2014-2673", "CVE-2014-2678", "CVE-2014-2706",
                "CVE-2014-2851");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for linux USN-2228-1");

  script_tag(name:"affected", value:"linux on Ubuntu 13.10");
  script_tag(name:"insight", value:"Matthew Daley reported an information leak in the floppy disk
driver of the Linux kernel. An unprivileged local user could exploit this flaw
to obtain potentially sensitive information from kernel memory. (CVE-2014-1738)

Matthew Daley reported a flaw in the handling of ioctl commands by the
floppy disk driver in the Linux kernel. An unprivileged local user could
exploit this flaw to gain administrative privileges if the floppy disk
module is loaded. (CVE-2014-1737)

A flaw was discovered in the vhost-net subsystem of the Linux kernel. Guest
OS users could exploit this flaw to cause a denial of service (host OS
crash). (CVE-2014-0055)

A flaw was discovered in the handling of network packets when mergeable
buffers are disabled for virtual machines in the Linux kernel. Guest OS
users may exploit this flaw to cause a denial of service (host OS crash) or
possibly gain privilege on the host OS. (CVE-2014-0077)

Nikolay Aleksandrov discovered a race condition in Linux kernel's IPv4
fragment handling code. Remote attackers could exploit this flaw to cause a
denial of service (system crash) or possibly have other unspecified impact.
(CVE-2014-0100)

A flaw was discovered in the Linux kernel's handling of the SCTP handshake.
A remote attacker could exploit this flaw to cause a denial of service
(system crash). (CVE-2014-0101)

A flaw was discovered in the handling of routing information in Linux
kernel's IPv6 stack. A remote attacker could exploit this flaw to cause a
denial of service (memory consumption) via a flood of ICMPv6 router
advertisement packets. (CVE-2014-2309)

An error was discovered in the Linux kernel's DCCP protocol support. A
remote attacked could exploit this flaw to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2014-2523)

Max Sydorenko discovered a race condition in the Atheros 9k wireless driver
in the Linux kernel. This race could be exploited by remote attackers to
cause a denial of service (system crash). (CVE-2014-2672)

Adhemerval Zanella Neto discovered a flaw the in the Transactional Memory
(TM) implementation for powerpc based machine. An unprivileged local user
could exploit this flaw to cause a denial of service (system crash).
(CVE-2014-2673)

An error was discovered in the Reliable Datagram Sockets (RDS) protocol
stack in the Linux kernel. A local user could exploit this flaw to cause a
denial of service (system crash) or possibly have unspecified other impact.
(CVE-2014-2678)

Yaara Rozenblum discovered a race condition in the Linux kernel's Generic
IEEE 802.11 Networking Stack (mac80211). Remote attackers could exploit
this flaw to ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2228-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
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

  if ((res = isdpkgvuln(pkg:"linux-image-3.11.0-22-generic", ver:"3.11.0-22.38", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.11.0-22-generic-lpae", ver:"3.11.0-22.38", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
