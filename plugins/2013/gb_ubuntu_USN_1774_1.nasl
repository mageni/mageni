###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1774_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for linux-ti-omap4 USN-1774-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1774-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.841371");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-22 10:41:42 +0530 (Fri, 22 Mar 2013)");
  script_cve_id("CVE-2013-0190", "CVE-2013-0216", "CVE-2013-0217", "CVE-2013-0231",
                "CVE-2013-0290", "CVE-2013-0311");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:S/C:C/I:C/A:C");
  script_name("Ubuntu Update for linux-ti-omap4 USN-1774-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.10");
  script_tag(name:"affected", value:"linux-ti-omap4 on Ubuntu 12.10");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Andrew Cooper of Citrix reported a Xen stack corruption in the Linux
  kernel. An unprivileged user in a 32bit PVOPS guest can cause the guest
  kernel to crash, or operate erroneously. (CVE-2013-0190)

  A failure to validate input was discovered in the Linux kernel's Xen
  netback (network backend) driver. A user in a guest OS may exploit this
  flaw to cause a denial of service to the guest OS and other guest domains.
  (CVE-2013-0216)

  A memory leak was discovered in the Linux kernel's Xen netback (network
  backend) driver. A user in a guest OS could trigger this flaw to cause a
  denial of service on the system. (CVE-2013-0217)

  A flaw was discovered in the Linux kernel Xen PCI backend driver. If a PCI
  device is assigned to the guest OS, the guest OS could exploit this flaw to
  cause a denial of service on the host. (CVE-2013-0231)

  Tommi Rantala discovered a flaw in the a flaw the Linux kernels handling of
  datagrams packets when the MSG_PEEK flag is specified. An unprivileged
  local user could exploit this flaw to cause a denial of service (system
  hang). (CVE-2013-0290)

  A flaw was discovered in the Linux kernel's vhost driver used to accelerate
  guest networking in KVM based virtual machines. A privileged guest user
  could exploit this flaw to crash the host system. (CVE-2013-0311)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"linux-image-3.5.0-221-omap4", ver:"3.5.0-221.31", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
