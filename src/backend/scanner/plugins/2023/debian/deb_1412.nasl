# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2007.1412");
  script_cve_id("CVE-2007-5162", "CVE-2007-5770");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1412)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1412");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1412");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby1.9' package(s) announced via the DSA-1412 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Ruby, an object-oriented scripting language. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-5162

It was discovered that the Ruby HTTP(S) module performs insufficient validation of SSL certificates, which may lead to man-in-the-middle attacks.

CVE-2007-5770

It was discovered that the Ruby modules for FTP, Telnet, IMAP, POP and SMTP perform insufficient validation of SSL certificates, which may lead to man-in-the-middle attacks.

The old stable distribution (sarge) doesn't contain ruby1.9 packages.

For the stable distribution (etch) these problems have been fixed in version 1.9.0+20060609-1etch1. Updated packages for hppa and sparc will be provided later.

We recommend that you upgrade your ruby1.9 packages.");

  script_tag(name:"affected", value:"'ruby1.9' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"irb1.9", ver:"1.9.0+20060609-1etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdbm-ruby1.9", ver:"1.9.0+20060609-1etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgdbm-ruby1.9", ver:"1.9.0+20060609-1etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenssl-ruby1.9", ver:"1.9.0+20060609-1etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libreadline-ruby1.9", ver:"1.9.0+20060609-1etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.9-dbg", ver:"1.9.0+20060609-1etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.9", ver:"1.9.0+20060609-1etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtcltk-ruby1.9", ver:"1.9.0+20060609-1etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rdoc1.9", ver:"1.9.0+20060609-1etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ri1.9", ver:"1.9.0+20060609-1etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9-dev", ver:"1.9.0+20060609-1etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9-elisp", ver:"1.9.0+20060609-1etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9-examples", ver:"1.9.0+20060609-1etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9", ver:"1.9.0+20060609-1etch1", rls:"DEB4"))) {
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
