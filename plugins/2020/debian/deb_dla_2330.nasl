# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892330");
  script_version("2020-08-17T13:22:39+0000");
  script_cve_id("CVE-2017-17742", "CVE-2019-16201", "CVE-2019-16254", "CVE-2019-16255", "CVE-2019-8320", "CVE-2019-8321", "CVE-2019-8322", "CVE-2019-8323", "CVE-2019-8324", "CVE-2019-8325");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-08-18 10:12:19 +0000 (Tue, 18 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-17 13:22:39 +0000 (Mon, 17 Aug 2020)");
  script_name("Debian LTS: Security Advisory for jruby (DLA-2330-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00027.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2330-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/925987");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jruby'
  package(s) announced via the DLA-2330-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were fixed in JRuby,
a 100% pure-Java implementation of Ruby.

CVE-2017-17742
CVE-2019-16254

HTTP Response Splitting attacks in the HTTP server of WEBrick.

CVE-2019-16201

Regular Expression Denial of Service vulnerability of WEBrick's
Digest access authentication.

CVE-2019-8320

Delete directory using symlink when decompressing tar.

CVE-2019-8321

Escape sequence injection vulnerability in verbose.

CVE-2019-8322

Escape sequence injection vulnerability in gem owner.

CVE-2019-8323

Escape sequence injection vulnerability in API response handling.

CVE-2019-8324

Installing a malicious gem may lead to arbitrary code execution.

CVE-2019-8325

Escape sequence injection vulnerability in errors.

CVE-2019-16255

Code injection vulnerability of Shell#[] and Shell#test.");

  script_tag(name:"affected", value:"'jruby' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1.7.26-1+deb9u2.

We recommend that you upgrade your jruby packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"jruby", ver:"1.7.26-1+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
