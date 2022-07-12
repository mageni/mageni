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
  script_oid("1.3.6.1.4.1.25623.1.0.705046");
  script_version("2022-01-17T14:05:15+0000");
  script_cve_id("CVE-2021-37956", "CVE-2021-37957", "CVE-2021-37958", "CVE-2021-37959", "CVE-2021-37961", "CVE-2021-37962", "CVE-2021-37963", "CVE-2021-37964", "CVE-2021-37965", "CVE-2021-37966", "CVE-2021-37967", "CVE-2021-37968", "CVE-2021-37969", "CVE-2021-37970", "CVE-2021-37971", "CVE-2021-37972", "CVE-2021-37973", "CVE-2021-37974", "CVE-2021-37975", "CVE-2021-37976", "CVE-2021-37977", "CVE-2021-37978", "CVE-2021-37979", "CVE-2021-37980", "CVE-2021-37981", "CVE-2021-37982", "CVE-2021-37983", "CVE-2021-37984", "CVE-2021-37985", "CVE-2021-37986", "CVE-2021-37987", "CVE-2021-37988", "CVE-2021-37989", "CVE-2021-37990", "CVE-2021-37991", "CVE-2021-37992", "CVE-2021-37993", "CVE-2021-37994", "CVE-2021-37995", "CVE-2021-37996", "CVE-2021-37997", "CVE-2021-37998", "CVE-2021-37999", "CVE-2021-38000", "CVE-2021-38001", "CVE-2021-38002", "CVE-2021-38003", "CVE-2021-38004", "CVE-2021-38005", "CVE-2021-38006", "CVE-2021-38007", "CVE-2021-38008", "CVE-2021-38009", "CVE-2021-38010", "CVE-2021-38011", "CVE-2021-38012", "CVE-2021-38013", "CVE-2021-38014", "CVE-2021-38015", "CVE-2021-38016", "CVE-2021-38017", "CVE-2021-38018", "CVE-2021-38019", "CVE-2021-38020", "CVE-2021-38021", "CVE-2021-38022", "CVE-2021-4052", "CVE-2021-4053", "CVE-2021-4054", "CVE-2021-4055", "CVE-2021-4056", "CVE-2021-4057", "CVE-2021-4058", "CVE-2021-4059", "CVE-2021-4061", "CVE-2021-4062", "CVE-2021-4063", "CVE-2021-4064", "CVE-2021-4065", "CVE-2021-4066", "CVE-2021-4067", "CVE-2021-4068", "CVE-2021-4078", "CVE-2021-4079", "CVE-2021-4098", "CVE-2021-4099", "CVE-2021-4100", "CVE-2021-4101", "CVE-2021-4102", "CVE-2022-0096", "CVE-2022-0097", "CVE-2022-0098", "CVE-2022-0099", "CVE-2022-0100", "CVE-2022-0101", "CVE-2022-0102", "CVE-2022-0103", "CVE-2022-0104", "CVE-2022-0105", "CVE-2022-0106", "CVE-2022-0107", "CVE-2022-0108", "CVE-2022-0109", "CVE-2022-0110", "CVE-2022-0111", "CVE-2022-0112", "CVE-2022-0113", "CVE-2022-0114", "CVE-2022-0115", "CVE-2022-0116", "CVE-2022-0117", "CVE-2022-0118", "CVE-2022-0120");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-01-18 10:59:48 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-12 22:39:00 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"creation_date", value:"2022-01-16 02:01:24 +0000 (Sun, 16 Jan 2022)");
  script_name("Debian: Security Advisory for chromium (DSA-5046-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5046.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5046-1");
  script_xref(name:"Advisory-ID", value:"DSA-5046-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the DSA-5046-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Chromium, which could result
in the execution of arbitrary code, denial of service or information
disclosure.");

  script_tag(name:"affected", value:"'chromium' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (buster), security support for Chromium
has been discontinued due to toolchain issues which no longer allow to
build current Chromium releases on buster. You can either upgrade to
the stable release (bullseye) or switch to a browser which continues
to receive security supports in buster (firefox-esr or browsers based
on webkit2gtk)

For the stable distribution (bullseye), these problems have been fixed in
version 97.0.4692.71-0.1~deb11u1.

We recommend that you upgrade your chromium packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"97.0.4692.71-0.1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-common", ver:"97.0.4692.71-0.1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"97.0.4692.71-0.1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"97.0.4692.71-0.1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-sandbox", ver:"97.0.4692.71-0.1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"97.0.4692.71-0.1~deb11u1", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
