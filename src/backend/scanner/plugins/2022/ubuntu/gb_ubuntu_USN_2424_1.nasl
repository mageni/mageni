# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2014.2424.1");
  script_cve_id("CVE-2014-1587", "CVE-2014-1588", "CVE-2014-1589", "CVE-2014-1590", "CVE-2014-1591", "CVE-2014-1592", "CVE-2014-1593", "CVE-2014-1594");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2424-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|14\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2424-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2424-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-2424-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gary Kwong, Randell Jesup, Nils Ohlmeier, Jesse Ruderman, Max Jonas
Werner, Christian Holler, Jon Coppeard, Eric Rahm, Byron Campen, Eric
Rescorla, and Xidorn Quan discovered multiple memory safety issues in
Firefox. If a user were tricked in to opening a specially crafted website,
an attacker could potentially exploit these to cause a denial of service
via application crash, or execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2014-1587, CVE-2014-1588)

Cody Crews discovered a way to trigger chrome-level XBL bindings from web
content in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
bypass security restrictions. (CVE-2014-1589)

Joe Vennix discovered a crash when using XMLHttpRequest in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service. (CVE-2014-1590)

Muneaki Nishimura discovered that CSP violation reports did not remove
path information in some circumstances. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to obtain sensitive information. (CVE-2014-1591)

Berend-Jan Wever discovered a use-after-free during HTML parsing. If a
user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via
application crash or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2014-1592)

Abhishek Arya discovered a buffer overflow when parsing media content. If
a user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via
application crash or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2014-1593)

Byoungyoung Lee, Chengyu Song, and Taesoo Kim discovered a bad cast in the
compositor. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause undefined
behaviour, a denial of service via application crash or execute arbitrary
code with the privileges of the user invoking Firefox. (CVE-2014-1594)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"34.0+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"34.0+build2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"34.0+build2-0ubuntu0.14.10.2", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
