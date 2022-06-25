###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3777_3.nasl 14288 2019-03-18 16:34:17Z cfischer $
#
# Ubuntu Update for linux-azure USN-3777-3
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
  script_oid("1.3.6.1.4.1.25623.1.0.843664");
  script_version("$Revision: 14288 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-10-23 11:50:44 +0200 (Tue, 23 Oct 2018)");
  script_cve_id("CVE-2018-17182", "CVE-2018-15594", "CVE-2018-15572", "CVE-2017-5715", "CVE-2018-14633", "CVE-2018-3639", "CVE-2018-6554", "CVE-2018-6555");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux-azure USN-3777-3");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"USN-3777-1 fixed vulnerabilities in the Linux kernel for Ubuntu 18.04
%LTS. This update provides the corresponding updates for the
Linux kernel for Azure Cloud systems.

Jann Horn discovered that the vmacache subsystem did not properly handle
sequence number overflows, leading to a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or execute arbitrary code. (CVE-2018-17182)

It was discovered that the paravirtualization implementation in the Linux
kernel did not properly handle some indirect calls, reducing the
effectiveness of Spectre v2 mitigations for paravirtual guests. A local
attacker could use this to expose sensitive information. (CVE-2018-15594)

It was discovered that microprocessors utilizing speculative execution and
prediction of return addresses via Return Stack Buffer (RSB) may allow
unauthorized memory reads via sidechannel attacks. An attacker could use
this to expose sensitive information. (CVE-2018-15572)

Jann Horn discovered that microprocessors utilizing speculative execution
and branch prediction may allow unauthorized memory reads via sidechannel
attacks. This flaw is known as Spectre. A local attacker could use this to
expose sensitive information, including kernel memory. (CVE-2017-5715)

It was discovered that a stack-based buffer overflow existed in the iSCSI
target implementation of the Linux kernel. A remote attacker could use this
to cause a denial of service (system crash). (CVE-2018-14633)

Jann Horn and Ken Johnson discovered that microprocessors utilizing
speculative execution of a memory read may allow unauthorized memory reads
via a sidechannel attack. This flaw is known as Spectre Variant 4. A local
attacker could use this to expose sensitive information, including kernel
memory. (CVE-2018-3639)

It was discovered that a memory leak existed in the IRDA subsystem of the
Linux kernel. A local attacker could use this to cause a denial of service
(kernel memory exhaustion). (CVE-2018-6554)

It was discovered that a use-after-free vulnerability existed in the IRDA
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2018-6555)");
  script_tag(name:"affected", value:"linux-azure on Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3777-3/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04 LTS|16\.04 LTS)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU18.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-4.15.0-1025-azure", ver:"4.15.0-1025.26", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1025.25", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-4.15.0-1025-azure", ver:"4.15.0-1025.26~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1025.31", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
