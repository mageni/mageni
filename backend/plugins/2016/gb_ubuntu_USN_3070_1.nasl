###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux USN-3070-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842875");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-08-30 05:43:50 +0200 (Tue, 30 Aug 2016)");
  script_cve_id("CVE-2016-1237", "CVE-2016-5244", "CVE-2016-5400", "CVE-2016-5696",
		"CVE-2016-5728", "CVE-2016-5828", "CVE-2016-5829", "CVE-2016-6197");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux USN-3070-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"A missing permission check when settings
  ACLs was discovered in nfsd. A local user could exploit this flaw to gain
  access to any file by setting an ACL. (CVE-2016-1237)

Kangjie Lu discovered an information leak in the Reliable Datagram Sockets
(RDS) implementation in the Linux kernel. A local attacker could use this
to obtain potentially sensitive information from kernel memory.
(CVE-2016-5244)

James Patrick-Evans discovered that the airspy USB device driver in the
Linux kernel did not properly handle certain error conditions. An attacker
with physical access could use this to cause a denial of service (memory
consumption). (CVE-2016-5400)

Yue Cao et al discovered a flaw in the TCP implementation's handling of
challenge acks in the Linux kernel. A remote attacker could use this to
cause a denial of service (reset connection) or inject content into an TCP
stream. (CVE-2016-5696)

Pengfei Wang discovered a race condition in the MIC VOP driver in the Linux
kernel. A local attacker could use this to cause a denial of service
(system crash) or obtain potentially sensitive information from kernel
memory. (CVE-2016-5728)

Cyril Bur discovered that on PowerPC platforms, the Linux kernel mishandled
transactional memory state on exec(). A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2016-5828)

It was discovered that a heap based buffer overflow existed in the USB HID
driver in the Linux kernel. A local attacker could use this cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2016-5829)

It was discovered that the OverlayFS implementation in the Linux kernel did
not properly verify dentry state before proceeding with unlink and rename
operations. A local attacker could use this to cause a denial of service
(system crash). (CVE-2016-6197)");
  script_tag(name:"affected", value:"linux on Ubuntu 16.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3070-1/");
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

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-36-generic", ver:"4.4.0-36.55", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-36-generic-lpae", ver:"4.4.0-36.55", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-36-lowlatency", ver:"4.4.0-36.55", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-36-powerpc-e500mc", ver:"4.4.0-36.55", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-36-powerpc-smp", ver:"4.4.0-36.55", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-36-powerpc64-emb", ver:"4.4.0-36.55", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-36-powerpc64-smp", ver:"4.4.0-36.55", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
