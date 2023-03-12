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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.521");
  script_cve_id("CVE-2016-2818", "CVE-2016-2819", "CVE-2016-2821", "CVE-2016-2822", "CVE-2016-2828", "CVE-2016-2831");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Debian: Security Advisory (DLA-521)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-521");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-521");
  script_xref(name:"URL", value:"https://glandium.org/blog/?p622");
  script_xref(name:"URL", value:"https://en.wikipedia.org/wiki/Mozilla_software_rebranded_by_Debian");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'firefox-esr' package(s) announced via the DLA-521 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in the Mozilla Firefox web browser: Multiple memory safety errors, buffer overflows and other implementation errors may lead to the execution of arbitrary code or spoofing.

Wait, Firefox? No more references to Iceweasel? That's right, Debian no longer applies a custom branding. Please see these links for further information:

[link moved to references]

[link moved to references]

Debian follows the extended support releases (ESR) of Firefox. Support for the 38.x series has ended, so starting with this update we're now following the 45.x releases and this update to the next ESR is also the point where we reapply the original branding.

Transition packages for the iceweasel packages are provided which automatically upgrade to the new version. Since new binary packages need to be installed, make sure to allow that in your upgrade procedure (e.g. by using 'apt-get dist-upgrade' instead of 'apt-get upgrade').

For Debian 7 Wheezy, these problems have been fixed in version 45.2.0esr-1~deb7u1.

We recommend that you upgrade your firefox-esr packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'firefox-esr' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-dbg", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-dev", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ach", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-af", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-all", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-an", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ar", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-as", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ast", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-az", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-be", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bg", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bn-bd", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bn-in", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-br", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bs", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ca", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-cs", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-cy", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-da", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-de", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-dsb", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-el", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-en-gb", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-en-za", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-eo", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-ar", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-cl", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-es", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-mx", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-et", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-eu", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fa", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ff", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fi", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fr", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fy-nl", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ga-ie", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gd", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gl", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gn", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gu-in", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-he", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hi-in", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hr", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hsb", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hu", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hy-am", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-id", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-is", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-it", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ja", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-kk", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-km", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-kn", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ko", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-lij", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-lt", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-lv", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-mai", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-mk", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ml", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-mr", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ms", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-nb-no", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-nl", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-nn-no", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-or", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pa-in", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pl", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pt-br", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pt-pt", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-rm", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ro", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ru", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-si", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sk", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sl", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-son", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sq", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sr", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sv-se", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ta", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-te", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-th", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-tr", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-uk", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-uz", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-vi", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-xh", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-zh-cn", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-zh-tw", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-esr", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-dbg", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-dev", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ach", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-af", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-all", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-an", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ar", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-as", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ast", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-az", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-be", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-bg", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-bn-bd", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-bn-in", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-br", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-bs", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ca", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-cs", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-cy", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-da", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-de", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-dsb", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-el", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-en-gb", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-en-za", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-eo", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-es-ar", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-es-cl", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-es-es", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-es-mx", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-et", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-eu", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fa", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ff", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fi", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fr", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fy-nl", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ga-ie", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-gd", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-gl", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-gn", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-gu-in", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-he", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hi-in", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hr", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hsb", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hu", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hy-am", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-id", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-is", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-it", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ja", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-kk", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-km", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-kn", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ko", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-lij", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-lt", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-lv", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-mai", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-mk", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ml", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-mr", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ms", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-nb-no", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-nl", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-nn-no", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-or", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-pa-in", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-pl", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-pt-br", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-pt-pt", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-rm", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ro", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ru", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-si", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sk", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sl", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-son", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sq", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sr", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sv-se", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ta", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-te", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-th", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-tr", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-uk", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-uz", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-vi", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-xh", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-zh-cn", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-zh-tw", ver:"1:45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel", ver:"45.2.0esr-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
