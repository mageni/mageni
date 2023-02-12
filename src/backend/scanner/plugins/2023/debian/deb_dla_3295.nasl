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
  script_oid("1.3.6.1.4.1.25623.1.0.893295");
  script_version("2023-01-31T10:08:41+0000");
  script_cve_id("CVE-2022-24785", "CVE-2022-31129");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-12 09:18:00 +0000 (Tue, 12 Apr 2022)");
  script_tag(name:"creation_date", value:"2023-01-31 02:00:13 +0000 (Tue, 31 Jan 2023)");
  script_name("Debian LTS: Security Advisory for node-moment (DLA-3295-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/01/msg00035.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3295-1");
  script_xref(name:"Advisory-ID", value:"DLA-3295-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1009327");
  script_xref(name:"URL", value:"https://bugs.debian.org/1014845");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'node-moment'
  package(s) announced via the DLA-3295-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Moment.js is a JavaScript date library for parsing, validating,
manipulating, and formatting dates. A couple of vulnerabilities
were reported as follows:

CVE-2022-24785

A path traversal vulnerability impacts npm (server) users of
Moment.js, especially if a user-provided locale string is directly
used to switch moment locale.

CVE-2022-31129

Affected versions of moment were found to use an inefficient
parsing algorithm. Specifically using string-to-date parsing in
moment (more specifically rfc2822 parsing, which is tried by
default) has quadratic (N^2) complexity on specific inputs. Users
may notice a noticeable slowdown is observed with inputs above 10k
characters. Users who pass user-provided strings without sanity
length checks to moment constructor are vulnerable to (Re)DoS
attacks.");

  script_tag(name:"affected", value:"'node-moment' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
2.24.0+ds-1+deb10u1.

We recommend that you upgrade your node-moment packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libjs-moment", ver:"2.24.0+ds-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"node-moment", ver:"2.24.0+ds-1+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
