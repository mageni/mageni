###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1765_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for apache2 USN-1765-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1765-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.841365");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-19 09:49:37 +0530 (Tue, 19 Mar 2013)");
  script_cve_id("CVE-2012-3499", "CVE-2012-4558", "CVE-2012-4557", "CVE-2013-1048");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Ubuntu Update for apache2 USN-1765-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04 LTS|11\.10|10\.04 LTS|8\.04 LTS|12\.10)");
  script_tag(name:"affected", value:"apache2 on Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Niels Heinen discovered that multiple modules incorrectly sanitized certain
  strings, which could result in browsers becoming vulnerable to cross-site
  scripting attacks when processing the output. With cross-site scripting
  vulnerabilities, if a user were tricked into viewing server output during a
  crafted server request, a remote attacker could exploit this to modify the
  contents, or steal confidential data (such as passwords), within the same
  domain. (CVE-2012-3499, CVE-2012-4558)

  It was discovered that the mod_proxy_ajp module incorrectly handled error
  states. A remote attacker could use this issue to cause the server to stop
  responding, resulting in a denial of service. This issue only applied to
  Ubuntu 8.04 LTS, Ubuntu 10.04 LTS and Ubuntu 11.10. (CVE-2012-4557)

  It was discovered that the apache2ctl script shipped in Ubuntu packages
  incorrectly created the lock directory. A local attacker could possibly use
  this issue to gain privileges. The symlink protections in Ubuntu 11.10 and
  later should reduce this vulnerability to a denial of service.
  (CVE-2013-1048)");
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

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.22-1ubuntu1.3", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.20-1ubuntu1.4", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.14-5ubuntu8.11", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.8-1ubuntu0.25", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.22-6ubuntu2.2", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
