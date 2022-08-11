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
  script_oid("1.3.6.1.4.1.25623.1.0.705151");
  script_version("2022-05-31T14:07:25+0000");
  script_cve_id("CVE-2021-21408", "CVE-2021-26119", "CVE-2021-26120", "CVE-2021-29454", "CVE-2022-29221");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-06-01 10:00:47 +0000 (Wed, 01 Jun 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-26 10:15:00 +0000 (Wed, 26 May 2021)");
  script_tag(name:"creation_date", value:"2022-05-31 08:35:31 +0000 (Tue, 31 May 2022)");
  script_name("Debian: Security Advisory for smarty3 (DSA-5151-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|11)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5151.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5151-1");
  script_xref(name:"Advisory-ID", value:"DSA-5151-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'smarty3'
  package(s) announced via the DSA-5151-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in smarty3, the compiling
PHP template engine. Template authors are able to run restricted static php
methods or even arbitrary PHP code by crafting a malicious math string or by
choosing an invalid {block} or {include} file name. If a math string was passed
through as user provided data to the math function, remote users were able to
run arbitrary PHP code as well.");

  script_tag(name:"affected", value:"'smarty3' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (buster), these problems have been fixed
in version 3.1.33+20180830.1.3a78a21f+selfpack1-1+deb10u1.

For the stable distribution (bullseye), these problems have been fixed in
version 3.1.39-2+deb11u1.

We recommend that you upgrade your smarty3 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"smarty3", ver:"3.1.33+20180830.1.3a78a21f+selfpack1-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"smarty3", ver:"3.1.39-2+deb11u1", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
