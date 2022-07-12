# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891735");
  script_version("2019-04-04T06:23:28+0000");
  script_cve_id("CVE-2019-8320", "CVE-2019-8322", "CVE-2019-8323", "CVE-2019-8324", "CVE-2019-8325");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-04-04 06:23:28 +0000 (Thu, 04 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-02 20:00:00 +0000 (Tue, 02 Apr 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1735-1] ruby2.1 security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00037.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1735-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby2.1'
  package(s) announced via the DSA-1735-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in rubygems embedded in
ruby2.1, the interpreted scripting language.

CVE-2019-8320

A Directory Traversal issue was discovered in RubyGems. Before
making new directories or touching files (which now include
path-checking code for symlinks), it would delete the target
destination.

CVE-2019-8322

The gem owner command outputs the contents of the API response
directly to stdout. Therefore, if the response is crafted, escape
sequence injection may occur.

CVE-2019-8323

Gem::GemcutterUtilities#with_response may output the API response to
stdout as it is. Therefore, if the API side modifies the response,
escape sequence injection may occur.

CVE-2019-8324

A crafted gem with a multi-line name is not handled correctly.
Therefore, an attacker could inject arbitrary code to the stub line
of gemspec, which is eval-ed by code in ensure_loadable_spec during
the preinstall check.

CVE-2019-8325

An issue was discovered in RubyGems 2.6 and later through 3.0.2.
Since Gem::CommandManager#run calls alert_error without escaping,
escape sequence injection is possible. (There are many ways to cause
an error.)");

  script_tag(name:"affected", value:"'ruby2.1' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
2.1.5-2+deb8u7.

We recommend that you upgrade your ruby2.1 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libruby2.1", ver:"2.1.5-2+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby2.1", ver:"2.1.5-2+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby2.1-dev", ver:"2.1.5-2+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby2.1-doc", ver:"2.1.5-2+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby2.1-tcltk", ver:"2.1.5-2+deb8u7", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);