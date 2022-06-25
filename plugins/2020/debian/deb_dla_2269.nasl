# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892269");
  script_version("2020-07-02T03:10:07+0000");
  script_cve_id("CVE-2020-4046", "CVE-2020-4047", "CVE-2020-4048", "CVE-2020-4049", "CVE-2020-4050");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-07-02 10:22:40 +0000 (Thu, 02 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-02 03:10:07 +0000 (Thu, 02 Jul 2020)");
  script_name("Debian LTS: Security Advisory for wordpress (DLA-2269-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00000.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2269-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/962685");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wordpress'
  package(s) announced via the DLA-2269-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Wordpress, a web
blogging tool. They allowed remote attackers to perform
various Cross-Side Scripting (XSS) attacks, create open
redirects, escalate privileges, and bypass authorization
access.

CVE-2020-4046

In affected versions of WordPress, users with low
privileges (like contributors and authors) can use the
embed block in a certain way to inject unfiltered HTML
in the block editor. When affected posts are viewed by a
higher privileged user, this could lead to script
execution in the editor/wp-admin.

CVE-2020-4047

In affected versions of WordPress, authenticated users with
upload permissions (like authors) are able to inject
JavaScript into some media file attachment pages in a certain
way. This can lead to script execution in the context of a
higher privileged user when the file is viewed by them.

CVE-2020-4048

In affected versions of WordPress, due to an issue in
wp_validate_redirect() and URL sanitization, an arbitrary
external link can be crafted leading to unintended/open
redirect when clicked.

CVE-2020-4049

In affected versions of WordPress, when uploading themes, the
name of the theme folder can be crafted in a way that could
lead to JavaScript execution in /wp-admin on the themes page.
This does require an admin to upload the theme, and is low
severity self-XSS.

CVE-2020-4050

In affected versions of WordPress, misuse of the
`set-screen-option` filter's return value allows arbitrary
user meta fields to be saved. It does require an admin to
install a plugin that would misuse the filter. Once installed,
it can be leveraged by low privileged users.");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
4.1.31+dfsg-0+deb8u1.

We recommend that you upgrade your wordpress packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"4.1.31+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"4.1.31+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentyfifteen", ver:"4.1.31+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentyfourteen", ver:"4.1.31+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentythirteen", ver:"4.1.31+dfsg-0+deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
