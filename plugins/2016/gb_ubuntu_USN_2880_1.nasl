###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for firefox USN-2880-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842618");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-01-28 06:33:01 +0100 (Thu, 28 Jan 2016)");
  script_cve_id("CVE-2016-1930", "CVE-2016-1931", "CVE-2016-1933", "CVE-2016-1935",
                "CVE-2016-1937", "CVE-2016-1938", "CVE-2016-1939", "CVE-2016-1942",
                "CVE-2016-1944", "CVE-2016-1945", "CVE-2016-1946", "CVE-2016-1947");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for firefox USN-2880-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Bob Clary, Christian Holler, Nils Ohlmeier,
  Gary Kwong, Jesse Ruderman, Carsten Book, Randell Jesup, Nicolas Pierron,
  Eric Rescorla, Tyson Smith, and Gabor Krizsanits discovered multiple memory
  safety issues in Firefox. If a user were tricked in to opening a specially
  crafted website, an attacker could potentially exploit these to cause a denial
  of service via application crash, or execute arbitrary code with the privileges
  of the user invoking Firefox. (CVE-2016-1930, CVE-2016-1931)

  Gustavo Grieco discovered an out-of-memory crash when loading GIF images
  in some circumstances. If a user were tricked in to opening a specially
  crafted website, an attacker could exploit this to cause a denial of
  service. (CVE-2016-1933)

  Aki Helin discovered a buffer overflow when rendering WebGL content in
  some circumstances. If a user were tricked in to opening a specially
  crafted website, an attacker could potentially exploit this to cause a
  denial of service via application crash, or execute arbitrary code with
  the privileges of the user invoking Firefox. (CVE-2016-1935)

  It was discovered that a delay was missing when focusing the protocol
  handler dialog. If a user were tricked in to opening a specially crafted
  website, an attacker could potentially exploit this to conduct
  clickjacking attacks. (CVE-2016-1937)

  Hanno B&#246 ck discovered that calculations with mp_div and mp_exptmod in NSS
  produce incorrect results in some circumstances, resulting in
  cryptographic weaknesses. (CVE-2016-1938)

  Nicholas Hurley discovered that Firefox allows for control characters to
  be set in cookie names. An attacker could potentially exploit this to
  conduct cookie injection attacks on some web servers. (CVE-2016-1939)

  It was discovered that when certain invalid URLs are pasted in to the
  addressbar, the addressbar contents may be manipulated to show the
  location of arbitrary websites. An attacker could potentially exploit this
  to conduct URL spoofing attacks. (CVE-2016-1942)

  Ronald Crane discovered three vulnerabilities through code inspection. If
  a user were tricked in to opening a specially crafted website, an attacker
  could potentially exploit these to cause a denial of service via
  application crash, or execute arbitrary code with the privileges of the
  user invoking Firefox. (CVE-2016-1944, CVE-2016-1945, CVE-2016-1946)

  Francois Marier discovered that Application Reputation lookups didn't
  work correctly, disabling warnings for potentially malicious downloads. An
  attacker could potentially exploit this by tricking a user in to
  downloading a malicious file. Other parts of the Safe Browsing feature
  were unaffected by this. (CVE-2016-1947)");
  script_tag(name:"affected", value:"firefox on Ubuntu 15.10,
  Ubuntu 15.04,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2880-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(15\.04|14\.04 LTS|12\.04 LTS|15\.10)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU15.04")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"44.0+build3-0ubuntu0.15.04.1", rls:"UBUNTU15.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"44.0+build3-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"44.0+build3-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU15.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"44.0+build3-0ubuntu0.15.10.1", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
