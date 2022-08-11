###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3361_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for linux-hwe USN-3361-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843249");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-07-22 07:23:26 +0200 (Sat, 22 Jul 2017)");
  script_cve_id("CVE-2015-1350", "CVE-2016-10208", "CVE-2016-8405", "CVE-2016-8636",
                "CVE-2016-9083", "CVE-2016-9084", "CVE-2016-9191", "CVE-2016-9604",
                "CVE-2016-9755", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-2596",
                "CVE-2017-2618", "CVE-2017-2671", "CVE-2017-5546", "CVE-2017-5549",
                "CVE-2017-5550", "CVE-2017-5551", "CVE-2017-5576", "CVE-2017-5669",
                "CVE-2017-5897", "CVE-2017-5970", "CVE-2017-6001", "CVE-2017-6214",
                "CVE-2017-6345", "CVE-2017-6346", "CVE-2017-6347", "CVE-2017-6348",
                "CVE-2017-7187", "CVE-2017-7261", "CVE-2017-7273", "CVE-2017-7472",
                "CVE-2017-7616", "CVE-2017-7618", "CVE-2017-7645", "CVE-2017-7889",
                "CVE-2017-7895", "CVE-2017-8924", "CVE-2017-8925", "CVE-2017-9150");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux-hwe USN-3361-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-hwe'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"USN-3358-1 fixed vulnerabilities in the
  Linux kernel for Ubuntu 17.04. This update provides the corresponding updates
  for the Linux Hardware Enablement (HWE) kernel from Ubuntu 17.04 for Ubuntu
  16.04 LTS. Please note that this update changes the Linux HWE kernel to the 4.10
  based kernel from Ubuntu 17.04, superseding the 4.8 based HWE kernel from Ubuntu
  16.10. Ben Harris discovered that the Linux kernel would strip extended
  privilege attributes of files when performing a failed unprivileged system call.
  A local attacker could use this to cause a denial of service. (CVE-2015-1350)
  Ralf Spenneberg discovered that the ext4 implementation in the Linux kernel did
  not properly validate meta block groups. An attacker with physical access could
  use this to specially craft an ext4 image that causes a denial of service
  (system crash). (CVE-2016-10208) Peter Pi discovered that the colormap handling
  for frame buffer devices in the Linux kernel contained an integer overflow. A
  local attacker could use this to disclose sensitive information (kernel memory).
  (CVE-2016-8405) It was discovered that an integer overflow existed in the
  InfiniBand RDMA over ethernet (RXE) transport implementation in the Linux
  kernel. A local attacker could use this to cause a denial of service (system
  crash) or possibly execute arbitrary code. (CVE-2016-8636) Vlad Tsyrklevich
  discovered an integer overflow vulnerability in the VFIO PCI driver for the
  Linux kernel. A local attacker with access to a vfio PCI device file could use
  this to cause a denial of service (system crash) or possibly execute arbitrary
  code. (CVE-2016-9083, CVE-2016-9084) CAI Qian discovered that the sysctl
  implementation in the Linux kernel did not properly perform reference counting
  in some situations. An unprivileged attacker could use this to cause a denial of
  service (system hang). (CVE-2016-9191) It was discovered that the keyring
  implementation in the Linux kernel in some situations did not prevent special
  internal keyrings from being joined by userspace keyrings. A privileged local
  attacker could use this to bypass module verification. (CVE-2016-9604) Dmitry
  Vyukov, Andrey Konovalov, Florian Westphal, and Eric Dumazet discovered that the
  netfiler subsystem in the Linux kernel mishandled IPv6 packet reassembly. A
  local user could use this to cause a denial of service (system crash) or
  possibly execute arbitrary code. (CVE-2016-9755) Andy Lutomirski and Willy
  Tarreau discovered that the KVM implementation in the Linux kernel did not
  properly emulate instructions on the SS segment register. A local attacker in a
  guest virtual machine could ... Description truncated, for more information
  please check the Reference URL");
  script_tag(name:"affected", value:"linux-hwe on Ubuntu 16.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3361-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04 LTS");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-4.10.0-27-generic", ver:"4.10.0-27.30~16.04.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.10.0-27-generic-lpae", ver:"4.10.0-27.30~16.04.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.10.0-27-lowlatency", ver:"4.10.0-27.30~16.04.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic-hwe-16.04", ver:"4.10.0.27.30", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-16.04", ver:"4.10.0.27.30", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-16.04", ver:"4.10.0.27.30", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
