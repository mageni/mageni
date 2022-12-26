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
  script_oid("1.3.6.1.4.1.25623.1.0.893210");
  script_version("2022-11-30T10:12:07+0000");
  script_cve_id("CVE-2021-40401", "CVE-2021-40403");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-11-30 10:12:07 +0000 (Wed, 30 Nov 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-31 18:10:00 +0000 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2022-11-29 02:00:13 +0000 (Tue, 29 Nov 2022)");
  script_name("Debian LTS: Security Advisory for gerbv (DLA-3210-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/11/msg00040.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3210-1");
  script_xref(name:"Advisory-ID", value:"DLA-3210-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gerbv'
  package(s) announced via the DLA-3210-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered gerbv, a Gerber file viewer. Most
Printed Circuit Board (PCB) design programs can export data to a
Gerber file.

* CVE-2021-40401: A use-after-free vulnerability existed in the
RS-274X aperture definition tokenization functionality. A
specially-crafted gerber file could have led to code execution.

* CVE-2021-40403: An information disclosure vulnerability existed in
the pick-and-place rotation parsing functionality. A
specially-crafted pick-and-place file could have exploited the
missing initialization of a structure in order to leak memory
contents.");

  script_tag(name:"affected", value:"'gerbv' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
2.7.0-1+deb10u2.

We recommend that you upgrade your gerbv packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"gerbv", ver:"2.7.0-1+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
