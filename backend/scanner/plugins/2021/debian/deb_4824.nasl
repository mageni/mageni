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
  script_oid("1.3.6.1.4.1.25623.1.0.704824");
  script_version("2021-01-12T07:15:51+0000");
  script_cve_id("CVE-2019-8075", "CVE-2020-15959", "CVE-2020-15960", "CVE-2020-15961", "CVE-2020-15962", "CVE-2020-15963", "CVE-2020-15964", "CVE-2020-15965", "CVE-2020-15966", "CVE-2020-15967", "CVE-2020-15968", "CVE-2020-15969", "CVE-2020-15970", "CVE-2020-15971", "CVE-2020-15972", "CVE-2020-15973", "CVE-2020-15974", "CVE-2020-15975", "CVE-2020-15976", "CVE-2020-15977", "CVE-2020-15978", "CVE-2020-15979", "CVE-2020-15980", "CVE-2020-15981", "CVE-2020-15982", "CVE-2020-15983", "CVE-2020-15984", "CVE-2020-15985", "CVE-2020-15986", "CVE-2020-15987", "CVE-2020-15988", "CVE-2020-15989", "CVE-2020-15990", "CVE-2020-15991", "CVE-2020-15992", "CVE-2020-15999", "CVE-2020-16000", "CVE-2020-16001", "CVE-2020-16002", "CVE-2020-16003", "CVE-2020-16004", "CVE-2020-16005", "CVE-2020-16006", "CVE-2020-16007", "CVE-2020-16008", "CVE-2020-16009", "CVE-2020-16011", "CVE-2020-16012", "CVE-2020-16013", "CVE-2020-16014", "CVE-2020-16015", "CVE-2020-16016", "CVE-2020-16017", "CVE-2020-16018", "CVE-2020-16019", "CVE-2020-16020", "CVE-2020-16021", "CVE-2020-16022", "CVE-2020-16023", "CVE-2020-16024", "CVE-2020-16025", "CVE-2020-16026", "CVE-2020-16027", "CVE-2020-16028", "CVE-2020-16029", "CVE-2020-16030", "CVE-2020-16031", "CVE-2020-16032", "CVE-2020-16033", "CVE-2020-16034", "CVE-2020-16035", "CVE-2020-16036", "CVE-2020-16037", "CVE-2020-16038", "CVE-2020-16039", "CVE-2020-16040", "CVE-2020-16041", "CVE-2020-16042", "CVE-2020-6510", "CVE-2020-6511", "CVE-2020-6512", "CVE-2020-6513", "CVE-2020-6514", "CVE-2020-6515", "CVE-2020-6516", "CVE-2020-6517", "CVE-2020-6518", "CVE-2020-6519", "CVE-2020-6520", "CVE-2020-6521", "CVE-2020-6522", "CVE-2020-6523", "CVE-2020-6524", "CVE-2020-6525", "CVE-2020-6526", "CVE-2020-6527", "CVE-2020-6528", "CVE-2020-6529", "CVE-2020-6530", "CVE-2020-6531", "CVE-2020-6532", "CVE-2020-6533", "CVE-2020-6534", "CVE-2020-6535", "CVE-2020-6536", "CVE-2020-6537", "CVE-2020-6538", "CVE-2020-6539", "CVE-2020-6540", "CVE-2020-6541", "CVE-2020-6542", "CVE-2020-6543", "CVE-2020-6544", "CVE-2020-6545", "CVE-2020-6546", "CVE-2020-6547", "CVE-2020-6548", "CVE-2020-6549", "CVE-2020-6550", "CVE-2020-6551", "CVE-2020-6552", "CVE-2020-6553", "CVE-2020-6554", "CVE-2020-6555", "CVE-2020-6556", "CVE-2020-6557", "CVE-2020-6558", "CVE-2020-6559", "CVE-2020-6560", "CVE-2020-6561", "CVE-2020-6562", "CVE-2020-6563", "CVE-2020-6564", "CVE-2020-6565", "CVE-2020-6566", "CVE-2020-6567", "CVE-2020-6568", "CVE-2020-6569", "CVE-2020-6570", "CVE-2020-6571", "CVE-2020-6573", "CVE-2020-6574", "CVE-2020-6575", "CVE-2020-6576");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-01-12 11:05:42 +0000 (Tue, 12 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-03 04:02:58 +0000 (Sun, 03 Jan 2021)");
  script_name("Debian: Security Advisory for chromium (DSA-4824-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4824.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4824-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the DSA-4824-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in the Chromium web browser, which
could result in the execution of arbitrary code, denial of service
or information disclosure.");

  script_tag(name:"affected", value:"'chromium' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), these problems have been fixed in
version 87.0.4280.88-0.4~deb10u1.

We recommend that you upgrade your chromium packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"87.0.4280.88-0.4~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-common", ver:"87.0.4280.88-0.4~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"87.0.4280.88-0.4~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"87.0.4280.88-0.4~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-sandbox", ver:"87.0.4280.88-0.4~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"87.0.4280.88-0.4~deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
