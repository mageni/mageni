###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3360_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for linux USN-3360-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.843250");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-07-22 07:25:26 +0200 (Sat, 22 Jul 2017)");
  script_cve_id("CVE-2014-9900", "CVE-2015-8944", "CVE-2015-8955", "CVE-2015-8962",
                "CVE-2015-8963", "CVE-2015-8964", "CVE-2015-8966", "CVE-2015-8967",
                "CVE-2016-10088", "CVE-2017-1000380", "CVE-2017-7346", "CVE-2017-7895",
                "CVE-2017-8924", "CVE-2017-8925", "CVE-2017-9605");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux USN-3360-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It was discovered that the Linux kernel did
  not properly initialize a Wake- on-Lan data structure. A local attacker could
  use this to expose sensitive information (kernel memory). (CVE-2014-9900) It was
  discovered that the Linux kernel did not properly restrict access to
  /proc/iomem. A local attacker could use this to expose sensitive information.
  (CVE-2015-8944) It was discovered that a use-after-free vulnerability existed in
  the performance events and counters subsystem of the Linux kernel for ARM64. A
  local attacker could use this to cause a denial of service (system crash) or
  possibly execute arbitrary code. (CVE-2015-8955) It was discovered that the SCSI
  generic (sg) driver in the Linux kernel contained a double-free vulnerability. A
  local attacker could use this to cause a denial of service (system crash).
  (CVE-2015-8962) Sasha Levin discovered that a race condition existed in the
  performance events and counters subsystem of the Linux kernel when handling CPU
  unplug events. A local attacker could use this to cause a denial of service
  (system crash) or possibly execute arbitrary code. (CVE-2015-8963) Tilman
  Schmidt and Sasha Levin discovered a use-after-free condition in the TTY
  implementation in the Linux kernel. A local attacker could use this to expose
  sensitive information (kernel memory). (CVE-2015-8964) It was discovered that
  the fcntl64() system call in the Linux kernel did not properly set memory limits
  when returning on 32-bit ARM processors. A local attacker could use this to gain
  administrative privileges. (CVE-2015-8966) It was discovered that the system
  call table for ARM 64-bit processors in the Linux kernel was not
  write-protected. An attacker could use this in conjunction with another kernel
  vulnerability to execute arbitrary code. (CVE-2015-8967) It was discovered that
  the generic SCSI block layer in the Linux kernel did not properly restrict write
  operations in certain situations. A local attacker could use this to cause a
  denial of service (system crash) or possibly gain administrative privileges.
  (CVE-2016-10088) Alexander Potapenko discovered a race condition in the Advanced
  Linux Sound Architecture (ALSA) subsystem in the Linux kernel. A local attacker
  could use this to expose sensitive information (kernel memory).
  (CVE-2017-1000380) Li Qiang discovered that the DRM driver for VMware Virtual
  GPUs in the Linux kernel did not properly validate some ioctl arguments. A local
  attacker could use this to cause a denial of service (system crash).
  (CVE-2017-7346) Tuomas Haanp&#228 &#228 and Ari Kauppi discovered that the NFSv2
  and NFSv3 server implementations i ... Description truncated, for more
  information please check the Reference URL");
  script_tag(name:"affected", value:"linux on Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3360-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-125-generic", ver:"3.13.0-125.174", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-125-generic-lpae", ver:"3.13.0-125.174", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-125-lowlatency", ver:"3.13.0-125.174", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-125-powerpc-e500", ver:"3.13.0-125.174", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-125-powerpc-e500mc", ver:"3.13.0-125.174", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-125-powerpc-smp", ver:"3.13.0-125.174", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-125-powerpc64-emb", ver:"3.13.0-125.174", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-125-powerpc64-smp", ver:"3.13.0-125.174", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic", ver:"3.13.0.125.135", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"3.13.0.125.135", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"3.13.0.125.135", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc-e500", ver:"3.13.0.125.135", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc-e500mc", ver:"3.13.0.125.135", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc-smp", ver:"3.13.0.125.135", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc64-emb", ver:"3.13.0.125.135", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc64-smp", ver:"3.13.0.125.135", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
