###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2070_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for linux-lts-saucy USN-2070-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841679");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-01-06 16:06:10 +0530 (Mon, 06 Jan 2014)");
  script_cve_id("CVE-2013-2929", "CVE-2013-2930", "CVE-2013-4345", "CVE-2013-4348",
                "CVE-2013-4511", "CVE-2013-4513", "CVE-2013-4514", "CVE-2013-4515",
                "CVE-2013-4516", "CVE-2013-6378", "CVE-2013-6380", "CVE-2013-6383",
                "CVE-2013-6763", "CVE-2013-7026");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_name("Ubuntu Update for linux-lts-saucy USN-2070-1");

  script_tag(name:"affected", value:"linux-lts-saucy on Ubuntu 12.04 LTS");
  script_tag(name:"insight", value:"Vasily Kulikov reported a flaw in the Linux kernel's implementation of
ptrace. An unprivileged local user could exploit this flaw to obtain
sensitive information from kernel memory. (CVE-2013-2929)

Dave Jones and Vince Weaver reported a flaw in the Linux kernel's per event
subsystem that allows normal users to enable function tracing. An
unprivileged local user could exploit this flaw to obtain potentially
sensitive information from the kernel. (CVE-2013-2930)

Stephan Mueller reported an error in the Linux kernel's ansi cprng random
number generator. This flaw makes it easier for a local attacker to break
cryptographic protections. (CVE-2013-4345)

Jason Wang discovered a bug in the network flow dissector in the Linux
kernel. A remote attacker could exploit this flaw to cause a denial of
service (infinite loop). (CVE-2013-4348)

Multiple integer overflow flaws were discovered in the Alchemy LCD frame-
buffer drivers in the Linux kernel. An unprivileged local user could
exploit this flaw to gain administrative privileges. (CVE-2013-4511)

Nico Golde and Fabian Yamaguchi reported a buffer overflow in the Ozmo
Devices USB over WiFi devices. A local user could exploit this flaw to
cause a denial of service or possibly unspecified impact. (CVE-2013-4513)

Nico Golde and Fabian Yamaguchi reported a flaw in the Linux kernel's
driver for Agere Systems HERMES II Wireless PC Cards. A local user with the
CAP_NET_ADMIN capability could exploit this flaw to cause a denial of
service or possibly gain administrative privileges. (CVE-2013-4514)

Nico Golde and Fabian Yamaguchi reported a flaw in the Linux kernel's
driver for Beceem WIMAX chipset based devices. An unprivileged local user
could exploit this flaw to obtain sensitive information from kernel memory.
(CVE-2013-4515)

Nico Golde and Fabian Yamaguchi reported a flaw in the Linux kernel's
driver for the SystemBase Multi-2/PCI serial card. An unprivileged user
could obtain sensitive information from kernel memory. (CVE-2013-4516)

Nico Golde and Fabian Yamaguchi reported a flaw in the Linux kernel's
debugfs filesystem. An administrative local user could exploit this flaw to
cause a denial of service (OOPS). (CVE-2013-6378)

Nico Golde and Fabian Yamaguchi reported a flaw in the driver for Adaptec
AACRAID scsi raid devices in the Linux kernel. A local user could use this
flaw to cause a denial of service or possibly other unspecified impact.
(CVE-2013-6380)

A flaw was discovered in the Linux kernel's compat ioctls for Adaptec
AACRAID scsi raid devices. An unprivileged local user could send
administrative commands to these devices potentia ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2070-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-saucy'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04 LTS");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-3.11.0-15-generic", ver:"3.11.0-15.23~precise1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.11.0-15-generic-lpae", ver:"3.11.0-15.23~precise1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
