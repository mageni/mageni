###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3507_2.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for linux-gcp USN-3507-2
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
  script_oid("1.3.6.1.4.1.25623.1.0.843395");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-12-08 07:04:27 +0100 (Fri, 08 Dec 2017)");
  script_cve_id("CVE-2017-16939", "CVE-2017-1000405", "CVE-2017-12193",
                "CVE-2017-15299", "CVE-2017-15306", "CVE-2017-15951");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux-gcp USN-3507-2");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gcp'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mohamed Ghannam discovered that a
  use-after-free vulnerability existed in the Netlink subsystem (XFRM) in the
  Linux kernel. A local attacker could use this to cause a denial of service
  (system crash) or possibly execute arbitrary code. (CVE-2017-16939) It was
  discovered that the Linux kernel did not properly handle copy-on- write of
  transparent huge pages. A local attacker could use this to cause a denial of
  service (application crashes) or possibly gain administrative privileges.
  (CVE-2017-1000405) Fan Wu, Haoran Qiu, and Shixiong Zhao discovered that the
  associative array implementation in the Linux kernel sometimes did not properly
  handle adding a new entry. A local attacker could use this to cause a denial of
  service (system crash). (CVE-2017-12193) Eric Biggers discovered that the key
  management subsystem in the Linux kernel did not properly restrict adding a key
  that already exists but is uninstantiated. A local attacker could use this to
  cause a denial of service (system crash) or possibly execute arbitrary code.
  (CVE-2017-15299) It was discovered that a null pointer dereference error existed
  in the PowerPC KVM implementation in the Linux kernel. A local attacker could
  use this to cause a denial of service (system crash). (CVE-2017-15306) Eric
  Biggers discovered a race condition in the key management subsystem of the Linux
  kernel around keys in a negative state. A local attacker could use this to cause
  a denial of service (system crash) or possibly execute arbitrary code.
  (CVE-2017-15951)");
  script_tag(name:"affected", value:"linux-gcp on Ubuntu 16.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3507-2/");
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

  if ((res = isdpkgvuln(pkg:"linux-image-4.13.0-1002-gcp", ver:"4.13.0-1002.5", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.13.0.1002.4", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.13.0.1002.4", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
