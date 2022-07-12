###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for oxide-qt USN-2920-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842685");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-03-11 06:01:59 +0100 (Fri, 11 Mar 2016)");
  script_cve_id("CVE-2016-1630", "CVE-2016-1631", "CVE-2016-1633", "CVE-2016-1634",
                "CVE-2016-1644", "CVE-2016-1636", "CVE-2016-1637", "CVE-2016-1641",
                "CVE-2016-1642", "CVE-2016-1643", "CVE-2016-2843", "CVE-2016-2844",
                "CVE-2016-2845");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for oxide-qt USN-2920-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxide-qt'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It was discovered that the
  ContainerNode::parserRemoveChild function in Blink mishandled widget updates
  in some circumstances. If a user were tricked in to opening a specially
  crafted website, an attacker could potentially exploit this to bypass
  same-origin restrictions. (CVE-2016-1630)

  It was discovered that the PPB_Flash_MessageLoop_Impl::InternalRun
  function in Chromium mishandled nested message loops. If a user were
  tricked in to opening a specially crafted website, an attacker could
  potentially exploit this to bypass same-origin restrictions.
  (CVE-2016-1631)

  Multiple use-after-frees were discovered in Blink. If a user were tricked
  in to opening a specially crafted website, an attacker could potentially
  exploit these to cause a denial of service via renderer crash or execute
  arbitrary code with the privileges of the sandboxed render process.
  (CVE-2016-1633, CVE-2016-1634, CVE-2016-1644)

  It was discovered that the PendingScript::notifyFinished function in
  Blink relied on memory-cache information about integrity-check occurrences
  instead of integrity-check successes. If a user were tricked in to opening
  a specially crafted website, an attacker could potentially exploit this to
  bypass Subresource Integrity (SRI) protections. (CVE-2016-1636)

  It was discovered that the SkATan2_255 function in Skia mishandled
  arctangent calculations. If a user were tricked in to opening a specially
  crafted website, an attacker could potentially exploit this to obtain
  sensitive information. (CVE-2016-1637)

  A use-after-free was discovered in Chromium. If a user were tricked in to
  opening a specially crafted website, an attacker could potentially exploit
  this to cause a denial of service via application crash, or execute
  arbitrary code with the privileges of the user invoking the program.
  (CVE-2016-1641)

  Multiple security issues were discovered in Chromium. If a user were
  tricked in to opening a specially crafted website, an attacker could
  potentially exploit these to read uninitialized memory, cause a denial
  of service via application crash or execute arbitrary code with the
  privileges of the user invoking the program. (CVE-2016-1642)

  A type-confusion bug was discovered in Blink. If a user were tricked in
  to opening a specially crafted website, an attacker could potentially
  exploit this to cause a denial of service via renderer crash or execute
  arbitrary code with the privileges of the sandboxed render process.
  (CVE-2016-1643)

  Multiple security issues were discovered in V8. If a user were tricked
  in to opening a specially crafted website, an attacker could potentially
  exploit these t ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"oxide-qt on Ubuntu 15.10,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2920-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|15\.10)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:i386", ver:"1.13.6-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:amd64", ver:"1.13.6-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU15.10")
{

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:i386", ver:"1.13.6-0ubuntu0.15.10.1", rls:"UBUNTU15.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:amd64", ver:"1.13.6-0ubuntu0.15.10.1", rls:"UBUNTU15.10")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}