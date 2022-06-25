###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux USN-2468-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842039");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-01-23 12:57:49 +0100 (Fri, 23 Jan 2015)");
  script_cve_id("CVE-2014-7841", "CVE-2014-7842", "CVE-2014-7843", "CVE-2014-8884");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_name("Ubuntu Update for linux USN-2468-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"A null pointer dereference flaw was discovered
in the the Linux kernel's SCTP implementation when ASCONF is used. A remote attacker
could exploit this flaw to cause a denial of service (system crash) via a malformed
INIT chunk. (CVE-2014-7841)

A race condition with MMIO and PIO transactions in the KVM (Kernel Virtual
Machine) subsystem of the Linux kernel was discovered. A guest OS user
could exploit this flaw to cause a denial of service (guest OS crash) via a
specially crafted application. (CVE-2014-7842)

Milo&#353  Prchl&#237 k reported a flaw in how the ARM64 platform handles a single
byte overflow in __clear_user. A local user could exploit this flaw to
cause a denial of service (system crash) by reading one byte beyond a
/dev/zero page boundary. (CVE-2014-7843)

A stack buffer overflow was discovered in the ioctl command handling for
the Technotrend/Hauppauge USB DEC devices driver. A local user could
exploit this flaw to cause a denial of service (system crash) or possibly
gain privileges. (CVE-2014-8884)");
  script_tag(name:"affected", value:"linux on Ubuntu 14.10");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2468-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.10");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.10")
{

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-29-generic", ver:"3.16.0-29.39", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-29-generic-lpae", ver:"3.16.0-29.39", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-29-lowlatency", ver:"3.16.0-29.39", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-29-powerpc-e500mc", ver:"3.16.0-29.39", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-29-powerpc-smp", ver:"3.16.0-29.39", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-29-powerpc64-emb", ver:"3.16.0-29.39", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-29-powerpc64-smp", ver:"3.16.0-29.39", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
