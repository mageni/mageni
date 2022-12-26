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
  script_oid("1.3.6.1.4.1.25623.1.0.705293");
  script_version("2022-12-07T10:11:17+0000");
  script_cve_id("CVE-2022-4174", "CVE-2022-4175", "CVE-2022-4176", "CVE-2022-4177", "CVE-2022-4178", "CVE-2022-4179", "CVE-2022-4180", "CVE-2022-4181", "CVE-2022-4182", "CVE-2022-4183", "CVE-2022-4184", "CVE-2022-4185", "CVE-2022-4186", "CVE-2022-4187", "CVE-2022-4188", "CVE-2022-4189", "CVE-2022-4190", "CVE-2022-4191", "CVE-2022-4192", "CVE-2022-4193", "CVE-2022-4194", "CVE-2022-4195");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-12-07 10:11:17 +0000 (Wed, 07 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-06 02:00:22 +0000 (Tue, 06 Dec 2022)");
  script_name("Debian: Security Advisory for chromium (DSA-5293-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5293.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5293-1");
  script_xref(name:"Advisory-ID", value:"DSA-5293-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the DSA-5293-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Chromium, which could result
in the execution of arbitrary code, denial of service or information
disclosure.");

  script_tag(name:"affected", value:"'chromium' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), these problems have been fixed in
version 108.0.5359.71-2~deb11u1.

We recommend that you upgrade your chromium packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"108.0.5359.71-2~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-common", ver:"108.0.5359.71-2~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"108.0.5359.71-2~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"108.0.5359.71-2~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-sandbox", ver:"108.0.5359.71-2~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"108.0.5359.71-2~deb11u1", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
