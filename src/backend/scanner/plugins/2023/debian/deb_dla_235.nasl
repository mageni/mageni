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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.235");
  script_cve_id("CVE-2011-0188", "CVE-2011-2705", "CVE-2012-4522", "CVE-2013-0256", "CVE-2013-2065", "CVE-2015-1855");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-30 12:27:00 +0000 (Wed, 30 Sep 2020)");

  script_name("Debian: Security Advisory (DLA-235)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-235");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-235");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby1.9.1' package(s) announced via the DLA-235 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2011-0188

The VpMemAlloc function in bigdecimal.c in the BigDecimal class in Ruby 1.9.2-p136 and earlier, as used on Apple Mac OS X before 10.6.7 and other platforms, does not properly allocate memory, which allows context-dependent attackers to execute arbitrary code or cause a denial of service (application crash) via vectors involving creation of a large BigDecimal value within a 64-bit process, related to an 'integer truncation issue.'

CVE-2011-2705

use upstream SVN r32050 to modify PRNG state to prevent random number sequence repeatation at forked child process which has same pid. Reported by Eric Wong.

CVE-2012-4522

The rb_get_path_check function in file.c in Ruby 1.9.3 before patchlevel 286 and Ruby 2.0.0 before r37163 allows context-dependent attackers to create files in unexpected locations or with unexpected names via a NUL byte in a file path.

CVE-2013-0256

darkfish.js in RDoc 2.3.0 through 3.12 and 4.x before 4.0.0.preview2.1, as used in Ruby, does not properly generate documents, which allows remote attackers to conduct cross-site scripting (XSS) attacks via a crafted URL.

CVE-2013-2065

(1) DL and (2) Fiddle in Ruby 1.9 before 1.9.3 patchlevel 426, and 2.0 before 2.0.0 patchlevel 195, do not perform taint checking for native functions, which allows context-dependent attackers to bypass intended $SAFE level restrictions.

CVE-2015-1855

OpenSSL extension hostname matching implementation violates RFC 6125");

  script_tag(name:"affected", value:"'ruby1.9.1' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.9.1-dbg", ver:"1.9.2.0-2+deb6u4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.9.1", ver:"1.9.2.0-2+deb6u4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtcltk-ruby1.9.1", ver:"1.9.2.0-2+deb6u4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ri1.9.1", ver:"1.9.2.0-2+deb6u4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1-dev", ver:"1.9.2.0-2+deb6u4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1-elisp", ver:"1.9.2.0-2+deb6u4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1-examples", ver:"1.9.2.0-2+deb6u4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1-full", ver:"1.9.2.0-2+deb6u4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1", ver:"1.9.2.0-2+deb6u4", rls:"DEB6"))) {
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
