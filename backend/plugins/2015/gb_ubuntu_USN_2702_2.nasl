###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for ubufox USN-2702-2
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842407");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-08-12 05:10:04 +0200 (Wed, 12 Aug 2015)");
  script_cve_id("CVE-2015-4473", "CVE-2015-4474", "CVE-2015-4475", "CVE-2015-4477",
                "CVE-2015-4478", "CVE-2015-4479", "CVE-2015-4480", "CVE-2015-4493",
                "CVE-2015-4484", "CVE-2015-4485", "CVE-2015-4486", "CVE-2015-4487",
                "CVE-2015-4488", "CVE-2015-4489", "CVE-2015-4490", "CVE-2015-4491",
                "CVE-2015-4492");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for ubufox USN-2702-2");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ubufox'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"USN-2702-1 fixed vulnerabilities in Firefox.
This update provides the corresponding updates for Ubufox.

Original advisory details:

Gary Kwong, Christian Holler, Byron Campen, Tyson Smith, Bobby Holley,
Chris Coulson, and Eric Rahm discovered multiple memory safety issues in
Firefox. If a user were tricked in to opening a specially crafted website,
an attacker could potentially exploit these to cause a denial of service
via application crash, or execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2015-4473, CVE-2015-4474)

Aki Helin discovered an out-of-bounds read when playing malformed MP3
content in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
obtain sensitive information, cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2015-4475)

A use-after-free was discovered during MediaStream playback in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2015-4477)

Andr&#233  Bargull discovered that non-configurable properties on javascript
objects could be redefined when parsing JSON. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to bypass same-origin restrictions. (CVE-2015-4478)

Multiple integer overflows were discovered in libstagefright. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2015-4479, CVE-2015-4480, CVE-2015-4493)

Jukka Jyl&#228 nki discovered a crash that occurs because javascript does not
properly gate access to Atomics or SharedArrayBuffers in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service. (CVE-2015-4484)

Abhishek Arya discovered 2 buffer overflows in libvpx when decoding
malformed WebM content in some circumstances. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit these to cause a denial of service via application crash, or
execute arbitrary code with the privileges of the user invoking Firefox.
(CVE-2015-4485, CVE-2015-4486)

Ronald Cran ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"ubufox on Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2702-2/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"3.1-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"3.1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
