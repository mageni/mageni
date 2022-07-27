###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3620_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for linux USN-3620-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.843498");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-04-06 09:57:34 +0200 (Fri, 06 Apr 2018)");
  script_cve_id("CVE-2017-11089", "CVE-2017-12762", "CVE-2017-17448", "CVE-2017-17741",
                "CVE-2017-17805", "CVE-2017-17807", "CVE-2018-1000026", "CVE-2018-5332");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux USN-3620-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It was discovered that the netlink 802.11
  configuration interface in the Linux kernel did not properly validate some
  attributes passed from userspace. A local attacker with the CAP_NET_ADMIN
  privilege could use this to cause a denial of service (system crash) or possibly
  execute arbitrary code. (CVE-2017-11089) It was discovered that a buffer
  overflow existed in the ioctl handling code in the ISDN subsystem of the Linux
  kernel. A local attacker could use this to cause a denial of service (system
  crash) or possibly execute arbitrary code. (CVE-2017-12762) It was discovered
  that the netfilter component of the Linux did not properly restrict access to
  the connection tracking helpers list. A local attacker could use this to bypass
  intended access restrictions. (CVE-2017-17448) Dmitry Vyukov discovered that the
  KVM implementation in the Linux kernel contained an out-of-bounds read when
  handling memory-mapped I/O. A local attacker could use this to expose sensitive
  information. (CVE-2017-17741) It was discovered that the Salsa20 encryption
  algorithm implementations in the Linux kernel did not properly handle
  zero-length inputs. A local attacker could use this to cause a denial of service
  (system crash). (CVE-2017-17805) It was discovered that the keyring
  implementation in the Linux kernel did not properly check permissions when a key
  request was performed on a task's' default keyring. A local attacker could use
  this to add keys to unauthorized keyrings. (CVE-2017-17807) It was discovered
  that the Broadcom NetXtremeII ethernet driver in the Linux kernel did not
  properly validate Generic Segment Offload (GSO) packet sizes. An attacker could
  use this to cause a denial of service (interface unavailability).
  (CVE-2018-1000026) It was discovered that the Reliable Datagram Socket (RDS)
  implementation in the Linux kernel contained an out-of-bounds write during RDMA
  page allocation. An attacker could use this to cause a denial of service (system
  crash) or possibly execute arbitrary code. (CVE-2018-5332)");
  script_tag(name:"affected", value:"linux on Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3620-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04 LTS");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-144-generic", ver:"3.13.0-144.193", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-144-generic-lpae", ver:"3.13.0-144.193", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-144-lowlatency", ver:"3.13.0-144.193", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-144-powerpc-e500", ver:"3.13.0-144.193", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-144-powerpc-e500mc", ver:"3.13.0-144.193", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-144-powerpc-smp", ver:"3.13.0-144.193", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-144-powerpc64-emb", ver:"3.13.0-144.193", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-144-powerpc64-smp", ver:"3.13.0-144.193", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic", ver:"3.13.0.144.154", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"3.13.0.144.154", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"3.13.0.144.154", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc-e500", ver:"3.13.0.144.154", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc-e500mc", ver:"3.13.0.144.154", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc-smp", ver:"3.13.0.144.154", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc64-emb", ver:"3.13.0.144.154", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc64-smp", ver:"3.13.0.144.154", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
