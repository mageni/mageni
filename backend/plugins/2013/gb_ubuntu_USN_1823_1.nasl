###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1823_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for thunderbird USN-1823-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841428");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-05-17 09:55:07 +0530 (Fri, 17 May 2013)");
  script_cve_id("CVE-2013-0801", "CVE-2013-1669", "CVE-2013-1670", "CVE-2013-1674",
                "CVE-2013-1675", "CVE-2013-1676", "CVE-2013-1677", "CVE-2013-1678",
                "CVE-2013-1679", "CVE-2013-1680", "CVE-2013-1681");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for thunderbird USN-1823-1");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1823-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04 LTS|12\.10|13\.04)");
  script_tag(name:"affected", value:"thunderbird on Ubuntu 13.04,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Multiple memory safety issues were discovered in Thunderbird. If the user
  were tricked into opening a specially crafted message with scripting
  enabled, an attacker could possibly exploit these to cause a denial of
  service via application crash, or potentially execute code with the
  privileges of the user invoking Thunderbird. (CVE-2013-0801,
  CVE-2013-1669)

  Cody Crews discovered that some constructors could be used to bypass
  restrictions enforced by their Chrome Object Wrapper (COW). If a user had
  scripting enabled, an attacker could exploit this to conduct cross-site
  scripting (XSS) attacks. (CVE-2013-1670)

  A use-after-free was discovered when resizing video content whilst it is
  playing. If a user had scripting enabled, an attacker could potentially
  exploit this to execute code with the privileges of the user invoking
  Thunderbird. (CVE-2013-1674)

  It was discovered that some DOMSVGZoomEvent functions could be used
  without being properly initialized, which could lead to information
  leakage. (CVE-2013-1675)

  Abhishek Arya discovered multiple memory safety issues in Thunderbird. If
  the user were tricked into opening a specially crafted message, an
  attacker could possibly exploit these to cause a denial of service via
  application crash, or potentially execute code with the privileges of
  the user invoking Thunderbird. (CVE-2013-1676, CVE-2013-1677,
  CVE-2013-1678, CVE-2013-1679, CVE-2013-1680, CVE-2013-1681)");
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

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.6+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.6+build1-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU13.04")
{
  ## Changed version to 17.0.6+build1-0ubuntu0.13.0 instead of 17.0.6+build1-0ubuntu0.13.04.1
  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"17.0.6+build1-0ubuntu0.13.0", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
