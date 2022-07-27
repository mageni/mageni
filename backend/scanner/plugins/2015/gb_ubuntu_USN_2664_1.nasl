###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-lts-utopic USN-2664-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842270");
  script_version("2019-05-24T11:20:30+0000");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2015-07-08 06:32:57 +0200 (Wed, 08 Jul 2015)");
  script_cve_id("CVE-2015-1420", "CVE-2015-4001", "CVE-2015-4002", "CVE-2015-4003",
                "CVE-2015-4167", "CVE-2015-4700");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux-lts-utopic USN-2664-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-utopic'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"A race condition was discovered in the
Linux kernel's file_handle size verification. A local user could exploit this
flaw to read potentially sensitive memory locations. (CVE-2015-1420)

A underflow error was discovered in the Linux kernel's Ozmo Devices USB
over WiFi host controller driver. A remote attacker could exploit this flaw
to cause a denial of service (system crash) or potentially execute
arbitrary code via a specially crafted packet. (CVE-2015-4001)

A bounds check error was discovered in the Linux kernel's Ozmo Devices USB
over WiFi host controller driver. A remote attacker could exploit this flaw
to cause a denial of service (system crash) or potentially execute
arbitrary code via a specially crafted packet. (CVE-2015-4002)

A division by zero error was discovered in the Linux kernel's Ozmo Devices
USB over WiFi host controller driver. A remote attacker could exploit this
flaw to cause a denial of service (system crash). (CVE-2015-4003)

Carl H Lunde discovered missing sanity checks in the the Linux kernel's UDF
file system (CONFIG_UDF_FS). A local attacker could exploit this flaw to
cause a denial of service (system crash) by using a corrupted file system
image. (CVE-2015-4167)

Daniel Borkmann reported a kernel crash in the Linux kernel's BPF filter
JIT optimization. A local attacker could exploit this flaw to cause a
denial of service (system crash). (CVE-2015-4700)");
  script_tag(name:"affected", value:"linux-lts-utopic on Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2664-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-43-generic", ver:"3.16.0-43.58~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-43-generic-lpae", ver:"3.16.0-43.58~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-43-lowlatency", ver:"3.16.0-43.58~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-43-powerpc-e500mc", ver:"3.16.0-43.58~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-43-powerpc-smp", ver:"3.16.0-43.58~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-43-powerpc64-emb", ver:"3.16.0-43.58~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-43-powerpc64-smp", ver:"3.16.0-43.58~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
