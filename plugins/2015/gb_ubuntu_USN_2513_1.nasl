###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux USN-2513-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842112");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-02-27 05:43:52 +0100 (Fri, 27 Feb 2015)");
  script_cve_id("CVE-2015-0239", "CVE-2013-7421", "CVE-2014-7970", "CVE-2014-8160",
                "CVE-2014-9529", "CVE-2014-9584", "CVE-2014-9585", "CVE-2014-9644");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux USN-2513-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"A flaw was discovered in the Kernel Virtual
Machine's (KVM) emulation of the SYSTENTER instruction when the guest OS does not
initialize the SYSENTER MSRs. A guest OS user could exploit this flaw to cause a
denial of service of the guest OS (crash) or potentially gain privileges on the
guest OS. (CVE-2015-0239)

A flaw was discovered in the automatic loading of modules in the crypto
subsystem of the Linux kernel. A local user could exploit this flaw to load
installed kernel modules, increasing the attack surface and potentially
using this to gain administrative privileges. (CVE-2013-7421)

Andy Lutomirski discovered a flaw in how the Linux kernel handles
pivot_root when used with a chroot directory. A local user could exploit
this flaw to cause a denial of service (mount-tree loop). (CVE-2014-7970)

A restriction bypass was discovered in iptables when conntrack rules are
specified and the conntrack protocol handler module is not loaded into the
Linux kernel. This flaw can cause the firewall rules on the system to be
bypassed when conntrack rules are used. (CVE-2014-8160)

A race condition was discovered in the Linux kernel's key ring. A local
user could cause a denial of service (memory corruption or panic) or
possibly have unspecified impact via the keyctl commands. (CVE-2014-9529)

A memory leak was discovered in the ISO 9660 CDROM file system when parsing
rock ridge ER records. A local user could exploit this flaw to obtain
sensitive information from kernel memory via a crafted iso9660 image.
(CVE-2014-9584)

A flaw was discovered in the Address Space Layout Randomization (ASLR) of
the Virtual Dynamically linked Shared Objects (vDSO) location. This flaw
makes it easier for a local user to bypass the ASLR protection mechanism.
(CVE-2014-9585)

A flaw was discovered in the crypto subsystem when screening module names
for automatic module loading if the name contained a valid crypto module
name, eg. vfat(aes). A local user could exploit this flaw to load installed
kernel modules, increasing the attack surface and potentially using this to
gain administrative privileges. (CVE-2014-9644)");
  script_tag(name:"affected", value:"linux on Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2513-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04 LTS");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-77-generic", ver:"3.2.0-77.112", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-77-generic-pae", ver:"3.2.0-77.112", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-77-highbank", ver:"3.2.0-77.112", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-77-omap", ver:"3.2.0-77.112", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-77-powerpc-smp", ver:"3.2.0-77.112", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-77-powerpc64-smp", ver:"3.2.0-77.112", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-77-virtual", ver:"3.2.0-77.112", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
