###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1593_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for devscripts USN-1593-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1593-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.841169");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-10-03 09:24:12 +0530 (Wed, 03 Oct 2012)");
  script_cve_id("CVE-2012-0212", "CVE-2012-2240", "CVE-2012-2241", "CVE-2012-2242", "CVE-2012-3500");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for devscripts USN-1593-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04 LTS|12\.04 LTS|11\.10|11\.04)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1593-1");
  script_tag(name:"affected", value:"devscripts on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Raphael Geissert discovered that the debdiff.pl tool incorrectly handled
  shell metacharacters. If a user or automated system were tricked into
  processing a specially crafted filename, a remote attacher could possibly
  execute arbitrary code. (CVE-2012-0212)

  Raphael Geissert discovered that the dscverify tool incorrectly escaped
  arguments to external commands. If a user or automated system were tricked
  into processing specially crafted files, a remote attacher could possibly
  execute arbitrary code. (CVE-2012-2240)

  Raphael Geissert discovered that the dget tool incorrectly performed input
  validation. If a user or automated system were tricked into processing
  specially crafted files, a remote attacher could delete arbitrary files.
  (CVE-2012-2241)

  Raphael Geissert discovered that the dget tool incorrectly escaped
  arguments to external commands. If a user or automated system were tricked
  into processing specially crafted files, a remote attacher could possibly
  execute arbitrary code. This issue only affected Ubuntu 10.04 LTS and
  Ubuntu 11.04. (CVE-2012-2242)

  Jim Meyering discovered that the annotate-output tool incorrectly handled
  temporary files. A local attacker could use this flaw to alter files being
  processed by the annotate-output tool. On Ubuntu 11.04 and later, this
  issue was mitigated by the Yama kernel symlink restrictions.
  (CVE-2012-3500)");
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

  if ((res = isdpkgvuln(pkg:"devscripts", ver:"2.10.61ubuntu5.3", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"devscripts", ver:"2.11.6ubuntu1.4", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"devscripts", ver:"2.11.1ubuntu3.2", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"devscripts", ver:"2.10.69ubuntu2.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
