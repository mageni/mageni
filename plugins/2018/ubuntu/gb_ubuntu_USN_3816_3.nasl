###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3816_3.nasl 14288 2019-03-18 16:34:17Z cfischer $
#
# Ubuntu Update for systemd USN-3816-3
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.843834");
  script_version("$Revision: 14288 $");
  script_cve_id("CVE-2018-6954", "CVE-2018-15686", "CVE-2018-15687");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-11-28 07:55:19 +0100 (Wed, 28 Nov 2018)");
  script_name("Ubuntu Update for systemd USN-3816-3");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04 LTS");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3816-3/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd'
  package(s) announced via the USN-3816-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3816-1 fixed vulnerabilities in systemd. The fix for CVE-2018-6954
caused a regression in systemd-tmpfiles when running Ubuntu inside a
container on some older kernels. This issue only affected Ubuntu 16.04
LTS. In order to continue to support this configuration, the fixes for
CVE-2018-6954 have been reverted.

We apologize for the inconvenience.

Original advisory details:

 Jann Horn discovered that unit_deserialize incorrectly handled status
messages
 above a certain length. A local attacker could potentially exploit this via
 NotifyAccess to inject arbitrary state across re-execution and obtain root
 privileges. (CVE-2018-15686)
 
 Jann Horn discovered a race condition in chown_one(). A local attacker
 could potentially exploit this by setting arbitrary permissions on certain
 files to obtain root privileges. This issue only affected Ubuntu 18.04 LTS
 and Ubuntu 18.10. (CVE-2018-15687)
 
 It was discovered that systemd-tmpfiles mishandled symlinks in
 non-terminal path components. A local attacker could potentially exploit
 this by gaining ownership of certain files to obtain root privileges. This
 issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2018-6954)");

  script_tag(name:"affected", value:"systemd on Ubuntu 16.04 LTS.");

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

if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"systemd", ver:"229-4ubuntu21.10", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
