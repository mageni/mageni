# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.704898");
  script_version("2021-04-23T03:00:18+0000");
  script_cve_id("CVE-2020-12695", "CVE-2021-0326", "CVE-2021-27803");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-04-23 10:26:07 +0000 (Fri, 23 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-23 03:00:18 +0000 (Fri, 23 Apr 2021)");
  script_name("Debian: Security Advisory for wpa (DSA-4898-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4898.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4898-1");
  script_xref(name:"Advisory-ID", value:"DSA-4898-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wpa'
  package(s) announced via the DSA-4898-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in wpa_supplicant and
hostapd.

CVE-2020-12695
It was discovered that hostapd does not properly handle UPnP
subscribe messages under certain conditions, allowing an attacker to
cause a denial of service.

CVE-2021-0326
It was discovered that wpa_supplicant does not properly process P2P
(Wi-Fi Direct) group information from active group owners. An
attacker within radio range of the device running P2P could take
advantage of this flaw to cause a denial of service or potentially
execute arbitrary code.

CVE-2021-27803
It was discovered that wpa_supplicant does not properly process
P2P (Wi-Fi Direct) provision discovery requests. An attacker
within radio range of the device running P2P could take advantage
of this flaw to cause a denial of service or potentially execute
arbitrary code.");

  script_tag(name:"affected", value:"'wpa' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), these problems have been fixed in
version 2:2.7+git20190128+0c1e29f-6+deb10u3.

We recommend that you upgrade your wpa packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"hostapd", ver:"2:2.7+git20190128+0c1e29f-6+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wpagui", ver:"2:2.7+git20190128+0c1e29f-6+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant", ver:"2:2.7+git20190128+0c1e29f-6+deb10u3", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
