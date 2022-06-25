###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2119_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for thunderbird USN-2119-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.841720");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-02-20 15:17:29 +0530 (Thu, 20 Feb 2014)");
  script_cve_id("CVE-2014-1477", "CVE-2014-1479", "CVE-2014-1482", "CVE-2014-1486",
                "CVE-2014-1487", "CVE-2014-1490", "CVE-2014-1491", "CVE-2014-1481",
                "CVE-2013-6674");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for thunderbird USN-2119-1");

  script_tag(name:"affected", value:"thunderbird on Ubuntu 13.10,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS");
  script_tag(name:"insight", value:"Christian Holler, Terrence Cole, Jesse Ruderman, Gary Kwong, Eric
Rescorla, Jonathan Kew, Dan Gohman, Ryan VanderMeulen and Sotaro Ikeda
discovered multiple memory safety issues in Thunderbird. If a user were
tricked in to opening a specially crafted message with scripting enabled,
an attacker could potentially exploit these to cause a denial of service
via application crash, or execute arbitrary code with the privileges of
the user invoking Thunderbird. (CVE-2014-1477)

Cody Crews discovered a method to bypass System Only Wrappers. If a user
had enabled scripting, an attacker could potentially exploit this to steal
confidential data or execute code with the privileges of the user invoking
Thunderbird. (CVE-2014-1479)

Fredrik L&#246 nnqvist discovered a use-after-free in Thunderbird. If a user
had enabled scripting, an attacker could potentially exploit this to cause
a denial of service via application crash, or execute arbitrary code with
the privileges of the user invoking Thunderbird. (CVE-2014-1482)

Arthur Gerkis discovered a use-after-free in Thunderbird. If a user had
enabled scripting, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code with
the privileges of the user invoking Thunderbird. (CVE-2014-1486)

Masato Kinugawa discovered a cross-origin information leak in web worker
error messages. If a user had enabled scripting, an attacker could
potentially exploit this to steal confidential information.
(CVE-2014-1487)

Several issues were discovered with ticket handling in NSS. An attacker
could potentially exploit these to cause a denial of service or bypass
cryptographic protection mechanisms. (CVE-2014-1490, CVE-2014-1491)

Boris Zbarsky discovered that security restrictions on window objects
could be bypassed under certain circumstances. (CVE-2014-1481)

Fabi&#225 n Cuchietti and Ateeq ur Rehman Khan discovered that it was possible
to bypass Javascript execution restrictions when replying to or forwarding
mail messages in certain circumstances. An attacker could potentially
exploit this to steal confidential information or modify message content.
(CVE-2013-6674)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2119-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04 LTS|13\.10|12\.10)");

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

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.3.0+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU13.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.3.0+build2-0ubuntu0.13.10.1", rls:"UBUNTU13.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.3.0+build2-0ubuntu0.12.10.1", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
