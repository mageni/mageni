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
  script_oid("1.3.6.1.4.1.25623.1.0.893304");
  script_version("2023-02-02T10:09:00+0000");
  script_cve_id("CVE-2020-21529", "CVE-2020-21531", "CVE-2020-21532", "CVE-2020-21676", "CVE-2021-32280");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-02-02 10:09:00 +0000 (Thu, 02 Feb 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-19 18:44:00 +0000 (Tue, 19 Oct 2021)");
  script_tag(name:"creation_date", value:"2023-02-01 02:00:08 +0000 (Wed, 01 Feb 2023)");
  script_name("Debian LTS: Security Advisory for fig2dev (DLA-3304-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/01/msg00044.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3304-1");
  script_xref(name:"Advisory-ID", value:"DLA-3304-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/960736");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fig2dev'
  package(s) announced via the DLA-3304-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Brief introduction

CVE-2020-21529

Stack buffer overflow in bezier_spline().

CVE-2020-21531

Global buffer overflow in conv_pattern_index().

CVE-2020-21532

Global buffer overflow in setfigfont().

CVE-2020-21676

Stack-based buffer overflow in genpstrx_text().

CVE-2021-32280

NULL pointer dereference in compute_closed_spline().");

  script_tag(name:"affected", value:"'fig2dev' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
1:3.2.7a-5+deb10u5.

We recommend that you upgrade your fig2dev packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"fig2dev", ver:"1:3.2.7a-5+deb10u5", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
