###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3359_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for linux USN-3359-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843247");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-07-21 07:18:04 +0200 (Fri, 21 Jul 2017)");
  script_cve_id("CVE-2014-9900", "CVE-2016-9755", "CVE-2017-1000380", "CVE-2017-5551",
                "CVE-2017-5576", "CVE-2017-7346", "CVE-2017-7895", "CVE-2017-8924",
                "CVE-2017-8925", "CVE-2017-9150", "CVE-2017-9605");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux USN-3359-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It was discovered that the Linux kernel did
  not properly initialize a Wake- on-Lan data structure. A local attacker could
  use this to expose sensitive information (kernel memory). (CVE-2014-9900) Dmitry
  Vyukov, Andrey Konovalov, Florian Westphal, and Eric Dumazet discovered that the
  netfiler subsystem in the Linux kernel mishandled IPv6 packet reassembly. A
  local user could use this to cause a denial of service (system crash) or
  possibly execute arbitrary code. (CVE-2016-9755) Alexander Potapenko discovered
  a race condition in the Advanced Linux Sound Architecture (ALSA) subsystem in
  the Linux kernel. A local attacker could use this to expose sensitive
  information (kernel memory). (CVE-2017-1000380) It was discovered that the Linux
  kernel did not clear the setgid bit during a setxattr call on a tmpfs
  filesystem. A local attacker could use this to gain elevated group privileges.
  (CVE-2017-5551) Murray McAllister discovered that an integer overflow existed in
  the VideoCore DRM driver of the Linux kernel. A local attacker could use this to
  cause a denial of service (system crash) or possibly execute arbitrary code.
  (CVE-2017-5576) Li Qiang discovered that the DRM driver for VMware Virtual GPUs
  in the Linux kernel did not properly validate some ioctl arguments. A local
  attacker could use this to cause a denial of service (system crash).
  (CVE-2017-7346) Tuomas Haanp&#228 &#228 and Ari Kauppi discovered that the NFSv2
  and NFSv3 server implementations in the Linux kernel did not properly check for
  the end of buffer. A remote attacker could use this to craft requests that cause
  a denial of service (system crash) or possibly execute arbitrary code.
  (CVE-2017-7895) It was discovered that an integer underflow existed in the
  Edgeport USB Serial Converter device driver of the Linux kernel. An attacker
  with physical access could use this to expose sensitive information (kernel
  memory). (CVE-2017-8924) It was discovered that the USB ZyXEL omni.net LCD PLUS
  driver in the Linux kernel did not properly perform reference counting. A local
  attacker could use this to cause a denial of service (tty exhaustion).
  (CVE-2017-8925) Jann Horn discovered that bpf in Linux kernel does not restrict
  the output of the print_bpf_insn function. A local attacker could use this to
  obtain sensitive address information. (CVE-2017-9150) Murray McAllister
  discovered that the DRM driver for VMware Virtual GPUs in the Linux kernel did
  not properly initialize memory. A local attacker could use this to expose
  sensitive information (kernel memory). (CVE-2017-9605)");
  script_tag(name:"affected", value:"linux on Ubuntu 16.10");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3359-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.10");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU16.10")
{

  if ((res = isdpkgvuln(pkg:"linux-image-4.8.0-1043-raspi2", ver:"4.8.0-1043.47", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.8.0-59-generic", ver:"4.8.0-59.64", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.8.0-59-generic-lpae", ver:"4.8.0-59.64", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.8.0-59-lowlatency", ver:"4.8.0-59.64", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.8.0-59-powerpc-e500mc", ver:"4.8.0-59.64", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.8.0-59-powerpc-smp", ver:"4.8.0-59.64", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.8.0-59-powerpc64-emb", ver:"4.8.0-59.64", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.8.0.59.72", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"4.8.0.59.72", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.8.0.59.72", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc-e500mc", ver:"4.8.0.59.72", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc-smp", ver:"4.8.0.59.72", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc64-emb", ver:"4.8.0.59.72", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"4.8.0.1043.47", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
