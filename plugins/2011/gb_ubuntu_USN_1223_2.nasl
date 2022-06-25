###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1223_2.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for puppet USN-1223-2
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1223-2/");
  script_oid("1.3.6.1.4.1.25623.1.0.840766");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-10-10 16:05:48 +0200 (Mon, 10 Oct 2011)");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:C/A:C");
  script_cve_id("CVE-2011-3869", "CVE-2011-3870", "CVE-2011-3871");
  script_name("Ubuntu Update for puppet USN-1223-2");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04 LTS");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1223-2");
  script_tag(name:"affected", value:"puppet on Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"USN-1223-1 fixed vulnerabilities in Puppet. A regression was found on
  Ubuntu 10.04 LTS that caused permission denied errors when managing SSH
  authorized_keys files with Puppet. This update fixes the problem.

  We apologize for the inconvenience.

  Original advisory details:

  It was discovered that Puppet unsafely opened files when the k5login type
  is used to manage files. A local attacker could exploit this to overwrite
  arbitrary files which could be used to escalate privileges. (CVE-2011-3869)

  Ricky Zhou discovered that Puppet did not drop privileges when creating
  SSH authorized_keys files. A local attacker could exploit this to overwrite
  arbitrary files as root. (CVE-2011-3870)

  It was discovered that Puppet used a predictable filename when using the --edit resource.
  A local attacker could exploit this to edit arbitrary files or run arbitrary code as the
  user invoking the program, typically root. (CVE-2011-3871)");
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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"puppet-common", ver:"0.25.4-2ubuntu6.4", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
