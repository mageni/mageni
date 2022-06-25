###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3878_1.nasl 14288 2019-03-18 16:34:17Z cfischer $
#
# Ubuntu Update for linux USN-3878-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.843895");
  script_version("$Revision: 14288 $");
  script_cve_id("CVE-2018-14625", "CVE-2018-16882", "CVE-2018-19407", "CVE-2018-19854");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-02-05 04:04:33 +0100 (Tue, 05 Feb 2019)");
  script_name("Ubuntu Update for linux USN-3878-1");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.10");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3878-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the USN-3878-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a race condition existed in the vsock address family
implementation of the Linux kernel that could lead to a use-after-free
condition. A local attacker in a guest virtual machine could use this to
expose sensitive information (host machine kernel memory). (CVE-2018-14625)

Cfir Cohen discovered that a use-after-free vulnerability existed in the
KVM implementation of the Linux kernel, when handling interrupts in
environments where nested virtualization is in use (nested KVM
virtualization is not enabled by default in Ubuntu kernels). A local
attacker in a guest VM could possibly use this to gain administrative
privileges in a host machine. (CVE-2018-16882)

Wei Wu discovered that the KVM implementation in the Linux kernel did not
properly ensure that ioapics were initialized. A local attacker could use
this to cause a denial of service (system crash). (CVE-2018-19407)

It was discovered that the crypto subsystem of the Linux kernel leaked
uninitialized memory to user space in some situations. A local attacker
could use this to expose sensitive information (kernel memory).
(CVE-2018-19854)");

  script_tag(name:"affected", value:"linux on Ubuntu 18.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "UBUNTU18.10")
{

  if ((res = isdpkgvuln(pkg:"linux-image-4.18.0-1006-gcp", ver:"4.18.0-1006.7", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.18.0-1007-kvm", ver:"4.18.0-1007.7", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.18.0-1008-aws", ver:"4.18.0-1008.10", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.18.0-1009-raspi2", ver:"4.18.0-1009.11", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.18.0-14-generic", ver:"4.18.0-14.15", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.18.0-14-generic-lpae", ver:"4.18.0-14.15", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.18.0-14-lowlatency", ver:"4.18.0-14.15", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.18.0-14-snapdragon", ver:"4.18.0-14.15", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.18.0.1008.8", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.18.0.1006.6", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.18.0.14.15", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"4.18.0.14.15", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.18.0.1006.6", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-kvm", ver:"4.18.0.1007.7", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.18.0.14.15", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"4.18.0.1009.6", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-snapdragon", ver:"4.18.0.14.15", rls:"UBUNTU18.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
