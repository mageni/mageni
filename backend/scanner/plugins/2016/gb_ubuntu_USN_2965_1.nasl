###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux USN-2965-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842762");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-05-17 16:25:21 +0200 (Tue, 17 May 2016)");
  script_cve_id("CVE-2016-4557", "CVE-2016-2184", "CVE-2016-2185", "CVE-2016-2186",
                "CVE-2016-2188", "CVE-2016-3136", "CVE-2016-3137", "CVE-2016-3138",
		"CVE-2016-3140", "CVE-2016-3156", "CVE-2016-3157", "CVE-2016-3672",
		"CVE-2016-3689", "CVE-2016-3951", "CVE-2016-3955");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux USN-2965-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Jann Horn discovered that the extended
  Berkeley Packet Filter (eBPF) implementation in the Linux kernel did not
  properly reference count file descriptors, leading to a use-after-free.
  A local unprivileged attacker could use this to gain administrative
  privileges. (CVE-2016-4557)

  Ralf Spenneberg discovered that the USB sound subsystem in the Linux kernel
  did not properly validate USB device descriptors. An attacker with physical
  access could use this to cause a denial of service (system crash).
  (CVE-2016-2184)

  Ralf Spenneberg discovered that the ATI Wonder Remote II USB driver in the
  Linux kernel did not properly validate USB device descriptors. An attacker
  with physical access could use this to cause a denial of service (system
  crash). (CVE-2016-2185)

  Ralf Spenneberg discovered that the PowerMate USB driver in the Linux
  kernel did not properly validate USB device descriptors. An attacker with
  physical access could use this to cause a denial of service (system crash).
  (CVE-2016-2186)

  Ralf Spenneberg discovered that the I/O-Warrior USB device driver in the
  Linux kernel did not properly validate USB device descriptors. An attacker
  with physical access could use this to cause a denial of service (system
  crash). (CVE-2016-2188)

  Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the
  MCT USB RS232 Converter device driver in the Linux kernel did not properly
  validate USB device descriptors. An attacker with physical access could use
  this to cause a denial of service (system crash). (CVE-2016-3136)

  Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the
  Cypress M8 USB device driver in the Linux kernel did not properly validate
  USB device descriptors. An attacker with physical access could use this to
  cause a denial of service (system crash). (CVE-2016-3137)

  Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the
  USB abstract device control driver for modems and ISDN adapters did not
  validate endpoint descriptors. An attacker with physical access could use
  this to cause a denial of service (system crash). (CVE-2016-3138)

  Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the
  Linux kernel's USB driver for Digi AccelePort serial converters did not
  properly validate USB device descriptors. An attacker with physical access
  could use this to cause a denial of service (system crash). (CVE-2016-3140)

  It was discovered that the IPv4 implementation in the Linux kernel did not
  perform the destruction of inet device objects properly. An attacker in a
  guest OS could use this to cause a denial of service (networking outage) ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"linux on Ubuntu 16.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2965-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-22-generic", ver:"4.4.0-22.39", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-22-generic-lpae", ver:"4.4.0-22.39", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-22-lowlatency", ver:"4.4.0-22.39", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-22-powerpc-e500mc", ver:"4.4.0-22.39", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-22-powerpc-smp", ver:"4.4.0-22.39", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-22-powerpc64-emb", ver:"4.4.0-22.39", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-22-powerpc64-smp", ver:"4.4.0-22.39", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
