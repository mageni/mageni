###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1616_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for python3.1 USN-1616-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1616-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.841199");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-10-26 09:50:43 +0530 (Fri, 26 Oct 2012)");
  script_cve_id("CVE-2008-5983", "CVE-2010-1634", "CVE-2010-2089", "CVE-2011-4944", "CVE-2012-0845", "CVE-2012-1150", "CVE-2012-2135");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for python3.1 USN-1616-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04 LTS|11\.04)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1616-1");
  script_tag(name:"affected", value:"python3.1 on Ubuntu 11.04,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"It was discovered that Python would prepend an empty string to sys.path
  under certain circumstances. A local attacker with write access to the
  current working directory could exploit this to execute arbitrary code.
  This issue only affected Ubuntu 10.04 LTS. (CVE-2008-5983)

  It was discovered that the audioop module did not correctly perform input
  validation. If a user or automatated system were tricked into opening a
  crafted audio file, an attacker could cause a denial of service via
  application crash. These issues only affected Ubuntu 10.04 LTS.
  (CVE-2010-1634, CVE-2010-2089)

  It was discovered that Python distutils contained a race condition when
  creating the ~/.pypirc file. A local attacker could exploit this to obtain
  sensitive information. (CVE-2011-4944)

  It was discovered that SimpleXMLRPCServer did not properly validate its
  input when handling HTTP POST requests. A remote attacker could exploit
  this to cause a denial of service via excessive CPU utilization.
  (CVE-2012-0845)

  It was discovered that Python was susceptible to hash algorithm attacks.
  An attacker could cause a denial of service under certain circumstances.
  This update adds the '-R' command line option and honors setting the
  PYTHONHASHSEED environment variable to 'random' to salt str and datetime
  objects with an unpredictable value. (CVE-2012-1150)

  Serhiy Storchaka discovered that the UTF16 decoder in Python did not
  properly reset internal variables after error handling. An attacker could
  exploit this to cause a denial of service via memory corruption.
  (CVE-2012-2135)");
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

  if ((res = isdpkgvuln(pkg:"python3.1", ver:"3.1.2-0ubuntu3.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python3.1-minimal", ver:"3.1.2-0ubuntu3.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"python3.1", ver:"3.1.3-1ubuntu1.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python3.1-minimal", ver:"3.1.3-1ubuntu1.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
