###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3632_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for linux-azure USN-3632-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843509");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-04-25 08:37:19 +0200 (Wed, 25 Apr 2018)");
  script_cve_id("CVE-2017-0861", "CVE-2017-1000407", "CVE-2017-15129", "CVE-2017-16994",
                "CVE-2017-17448", "CVE-2017-17450", "CVE-2017-17741", "CVE-2017-17805",
                "CVE-2017-17806", "CVE-2017-17807", "CVE-2018-1000026", "CVE-2018-5332",
                "CVE-2018-5333", "CVE-2018-5344", "CVE-2018-8043");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux-azure USN-3632-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It was discovered that a race condition
  leading to a use-after-free vulnerability existed in the ALSA PCM subsystem of
  the Linux kernel. A local attacker could use this to cause a denial of service
  (system crash) or possibly execute arbitrary code. (CVE-2017-0861) It was
  discovered that the KVM implementation in the Linux kernel allowed passthrough
  of the diagnostic I/O port 0x80. An attacker in a guest VM could use this to
  cause a denial of service (system crash) in the host OS. (CVE-2017-1000407) It
  was discovered that a use-after-free vulnerability existed in the network
  namespaces implementation in the Linux kernel. A local attacker could use this
  to cause a denial of service (system crash) or possibly execute arbitrary code.
  (CVE-2017-15129) It was discovered that the HugeTLB component of the Linux
  kernel did not properly handle holes in hugetlb ranges. A local attacker could
  use this to expose sensitive information (kernel memory). (CVE-2017-16994) It
  was discovered that the netfilter component of the Linux did not properly
  restrict access to the connection tracking helpers list. A local attacker could
  use this to bypass intended access restrictions. (CVE-2017-17448) It was
  discovered that the netfilter passive OS fingerprinting (xt_osf) module did not
  properly perform access control checks. A local attacker could improperly modify
  the system-wide OS fingerprint list. (CVE-2017-17450) Dmitry Vyukov discovered
  that the KVM implementation in the Linux kernel contained an out-of-bounds read
  when handling memory-mapped I/O. A local attacker could use this to expose
  sensitive information. (CVE-2017-17741) It was discovered that the Salsa20
  encryption algorithm implementations in the Linux kernel did not properly handle
  zero-length inputs. A local attacker could use this to cause a denial of service
  (system crash). (CVE-2017-17805) It was discovered that the HMAC implementation
  did not validate the state of the underlying cryptographic hash algorithm. A
  local attacker could use this to cause a denial of service (system crash) or
  possibly execute arbitrary code. (CVE-2017-17806) It was discovered that the
  keyring implementation in the Linux kernel did not properly check permissions
  when a key request was performed on a task's default keyring. A local attacker
  could use this to add keys to unauthorized keyrings. (CVE-2017-17807) It was
  discovered that the Broadcom NetXtremeII ethernet driver in the Linux kernel did
  not properly validate Generic Segment Offload (GSO) packet sizes. An attacker
  could use this to cause a denial of service (interface unavailability).
  (CVE-2018-1000 ... Description truncated, for more information please check the
  Reference URL");
  script_tag(name:"affected", value:"linux-azure on Ubuntu 16.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3632-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

  if ((res = isdpkgvuln(pkg:"linux-image-4.13.0-1014-azure", ver:"4.13.0-1014.17", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.13.0.1014.16", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
