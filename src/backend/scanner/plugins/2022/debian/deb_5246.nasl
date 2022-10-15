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
  script_oid("1.3.6.1.4.1.25623.1.0.705246");
  script_version("2022-10-06T10:41:20+0000");
  script_cve_id("CVE-2021-44854", "CVE-2021-44855", "CVE-2021-44856", "CVE-2022-28201", "CVE-2022-28202", "CVE-2022-28203", "CVE-2022-29248", "CVE-2022-31042", "CVE-2022-31043", "CVE-2022-31090", "CVE-2022-31091", "CVE-2022-34911", "CVE-2022-34912", "CVE-2022-41765", "CVE-2022-41767");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-10-06 10:41:20 +0000 (Thu, 06 Oct 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-07 18:26:00 +0000 (Tue, 07 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-10-05 07:22:12 +0000 (Wed, 05 Oct 2022)");
  script_name("Debian: Security Advisory for mediawiki (DSA-5246-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5246.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5246-1");
  script_xref(name:"Advisory-ID", value:"DSA-5246-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mediawiki'
  package(s) announced via the DSA-5246-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MediaWiki, a website engine
for collaborative work, which could result in restriction bypass,
information leaks, cross-site scripting or denial of service.");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), these problems have been fixed in
version 1:1.35.8-1~deb11u1.

We recommend that you upgrade your mediawiki packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"mediawiki", ver:"1:1.35.8-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mediawiki-classes", ver:"1:1.35.8-1~deb11u1", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
