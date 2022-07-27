###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux USN-2947-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842710");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-04-07 05:01:10 +0200 (Thu, 07 Apr 2016)");
  script_cve_id("CVE-2015-7833", "CVE-2015-8812", "CVE-2016-2085", "CVE-2016-2383",
                "CVE-2016-2550", "CVE-2016-2847");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux USN-2947-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Ralf Spenneberg discovered that the
  usbvision driver in the Linux kernel did not properly sanity check the interfaces
  and endpoints reported by the device. An attacker with physical access
  could cause a denial of service (system crash). (CVE-2015-7833)

  Venkatesh Pottem discovered a use-after-free vulnerability in the Linux
  kernel's CXGB3 driver. A local attacker could use this to cause a denial of
  service (system crash) or possibly execute arbitrary code. (CVE-2015-8812)

  Xiaofei Rex Guo discovered a timing side channel vulnerability in the Linux
  Extended Verification Module (EVM). An attacker could use this to affect
  system integrity. (CVE-2016-2085)

  It was discovered that the extended Berkeley Packet Filter (eBPF)
  implementation in the Linux kernel did not correctly compute branch offsets
  for backward jumps after ctx expansion. A local attacker could use this to
  cause a denial of service (system crash) or possibly execute arbitrary
  code. (CVE-2016-2383)

  David Herrmann discovered that the Linux kernel incorrectly accounted file
  descriptors to the original opener for in-flight file descriptors sent over
  a unix domain socket. A local attacker could use this to cause a denial of
  service (resource exhaustion). (CVE-2016-2550)

  It was discovered that the Linux kernel did not enforce limits on the
  amount of data allocated to buffer pipes. A local attacker could use this
  to cause a denial of service (resource exhaustion). (CVE-2016-2847)");
  script_tag(name:"affected", value:"linux on Ubuntu 15.10");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2947-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU15\.10");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU15.10")
{

  if ((res = isdpkgvuln(pkg:"linux-image-4.2.0-35-generic", ver:"4.2.0-35.40", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.2.0-35-generic-lpae", ver:"4.2.0-35.40", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.2.0-35-lowlatency", ver:"4.2.0-35.40", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.2.0-35-powerpc-e500mc", ver:"4.2.0-35.40", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.2.0-35-powerpc-smp", ver:"4.2.0-35.40", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.2.0-35-powerpc64-emb", ver:"4.2.0-35.40", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.2.0-35-powerpc64-smp", ver:"4.2.0-35.40", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
