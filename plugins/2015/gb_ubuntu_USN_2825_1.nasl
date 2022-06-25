###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for oxide-qt USN-2825-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842556");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-12-11 05:47:48 +0100 (Fri, 11 Dec 2015)");
  script_cve_id("CVE-2015-6765", "CVE-2015-6766", "CVE-2015-6767", "CVE-2015-6768",
                "CVE-2015-6770", "CVE-2015-6769", "CVE-2015-6771", "CVE-2015-6772",
                "CVE-2015-6773", "CVE-2015-6777", "CVE-2015-6782", "CVE-2015-6784",
                "CVE-2015-6785", "CVE-2015-6786", "CVE-2015-6787", "CVE-2015-8478");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for oxide-qt USN-2825-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxide-qt'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple use-after-free bugs were discovered
in the application cache implementation in Chromium. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit these to
cause a denial of service via application crash, or execute arbitrary code
with the privileges of the user invoking the program. (CVE-2015-6765,
CVE-2015-6766, CVE-2015-6767)

Several security issues were discovered in the DOM implementation in
Chromium. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to bypass same
origin restrictions. (CVE-2015-6768, CVE-2015-6770)

A security issue was discovered in the provisional-load commit
implementation in Chromium. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
bypass same origin restrictions. (CVE-2015-6769)

An out-of-bounds read was discovered in the array map and filter
operations in V8 in some circumstances. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash.
(CVE-2015-6771)

It was discovered that the DOM implementation in Chromium does not prevent
javascript: URL navigation while a document is being detached. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit this to bypass same origin restrictions.
(CVE-2015-6772)

An out-of bounds read was discovered in Skia in some circumstances. If a
user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via renderer
crash. (CVE-2015-6773)

A use-after-free was discovered in the DOM implementation in Chromium. If
a user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via renderer
crash or execute arbitrary code with the privileges of the sandboxed
render process. (CVE-2015-6777)

It was discovered that the Document::open function in Chromium did not
ensure that page-dismissal event handling is compatible with modal dialog
blocking. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to spoof application
UI content. (CVE-2015-6782)

It was discovered that the page serializer in Chromium mishandled MOTW
comments for URLs in some circumstances. An attacker could potentially
exploit this to inject HTML content. (CVE-2015-6784)

It was discovered that the Content Security Pol ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"oxide-qt on Ubuntu 15.10,
  Ubuntu 15.04,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2825-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(15\.04|14\.04 LTS|15\.10)");

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

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:amd64", ver:"1.11.3-0ubuntu0.15.04.1", rls:"UBUNTU15.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:i386", ver:"1.11.3-0ubuntu0.15.04.1", rls:"UBUNTU15.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:amd64", ver:"1.11.3-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:i386", ver:"1.11.3-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU15.10")
{
  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:amd64", ver:"1.11.3-0ubuntu0.15.10.1", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:i386", ver:"1.11.3-0ubuntu0.15.10.1", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
