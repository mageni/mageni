###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-lts-saucy USN-2137-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.841736");
  script_version("2019-05-24T11:20:30+0000");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2014-03-12 09:30:13 +0530 (Wed, 12 Mar 2014)");
  script_cve_id("CVE-2014-1690", "CVE-2014-1874", "CVE-2014-2038");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:N/I:N/A:C");
  script_name("Ubuntu Update for linux-lts-saucy USN-2137-1");

  script_tag(name:"affected", value:"linux-lts-saucy on Ubuntu 12.04 LTS");
  script_tag(name:"insight", value:"An information leak was discovered in the Linux kernel when
built with the NetFilter Connection Tracking (NF_CONNTRACK) support for IRC
protocol (NF_NAT_IRC). A remote attacker could exploit this flaw to obtain
potentially sensitive kernel information when communicating over a client-
to-client IRC connection(/dcc) via a NAT-ed network. (CVE-2014-1690)

Matthew Thode reported a denial of service vulnerability in the Linux
kernel when SELinux support is enabled. A local user with the CAP_MAC_ADMIN
capability (and the SELinux mac_admin permission if running in enforcing
mode) could exploit this flaw to cause a denial of service (kernel crash).
(CVE-2014-1874)

An information leak was discovered in the Linux kernel's NFS filesystem. A
local users with write access to an NFS share could exploit this flaw to
obtain potential sensitive information from kernel memory. (CVE-2014-2038)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2137-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-saucy'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

  if ((res = isdpkgvuln(pkg:"linux-image-3.11.0-18-generic", ver:"3.11.0-18.32~precise1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.11.0-18-generic-lpae", ver:"3.11.0-18.32~precise1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
