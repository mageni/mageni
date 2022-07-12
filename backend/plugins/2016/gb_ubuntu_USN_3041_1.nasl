###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for oxide-qt USN-3041-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842848");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-08-06 05:37:10 +0200 (Sat, 06 Aug 2016)");
  script_cve_id("CVE-2016-1705", "CVE-2016-1706", "CVE-2016-1710", "CVE-2016-1711",
		"CVE-2016-5127", "CVE-2016-5128", "CVE-2016-5129", "CVE-2016-5130",
 		"CVE-2016-5131", "CVE-2016-5132", "CVE-2016-5133", "CVE-2016-5134",
 		"CVE-2016-5135", "CVE-2016-5137");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for oxide-qt USN-3041-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxide-qt'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple security issues were discovered
  in Chromium. If a user were tricked in to opening a specially crafted website,
  an attacker could potentially exploit these to read uninitialized memory,
  cause a denial of service (application crash) or execute arbitrary code.
  (CVE-2016-1705)

It was discovered that the PPAPI implementation does not validate the
origin of IPC messages to the plugin broker process. A remote attacker
could potentially exploit this to bypass sandbox protection mechanisms.
(CVE-2016-1706)

It was discovered that Blink does not prevent window creation by a
deferred frame. A remote attacker could potentially exploit this to bypass
same origin restrictions. (CVE-2016-1710)

It was discovered that Blink does not disable frame navigation during a
detach operation on a DocumentLoader object. A remote attacker could
potentially exploit this to bypass same origin restrictions.
(CVE-2016-1711)

A use-after-free was discovered in Blink. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via renderer process crash, or execute
arbitrary code. (CVE-2016-5127)

It was discovered that objects.cc in V8 does not prevent API interceptors
from modifying a store target without setting a property. A remote
attacker could potentially exploit this to bypass same origin
restrictions. (CVE-2016-5128)

A memory corruption was discovered in V8. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via renderer process crash, or execute
arbitrary code. (CVE-2016-5129)

A security issue was discovered in Chromium. A remote attacker could
potentially exploit this to spoof the currently displayed URL.
(CVE-2016-5130)

A use-after-free was discovered in libxml. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via renderer process crash, or execute
arbitrary code. (CVE-2016-5131)

The Service Workers implementation in Chromium does not properly implement
the Secure Contexts specification during decisions about whether to
control a subframe. A remote attacker could potentially exploit this to
bypass same origin restrictions. (CVE-2016-5132)

It was discovered that Chromium mishandles origin information during proxy
authentication. A man-in-the-middle attacker could potentially exploit this
to spoof a proxy authentication login prompt. (CVE-2016-5133)

It was discovered that the Proxy Auto-Config (PAC) feature in Chromium
does  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"oxide-qt on Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3041-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|16\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:i386", ver:"1.16.5-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:amd64", ver:"1.16.5-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:i386", ver:"1.16.5-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"liboxideqtcore0:amd64", ver:"1.16.5-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}