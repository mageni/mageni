###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_813.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 813-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.890813");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2017-5488", "CVE-2017-5489", "CVE-2017-5490", "CVE-2017-5491", "CVE-2017-5492", "CVE-2017-5493", "CVE-2017-5610", "CVE-2017-5611", "CVE-2017-5612");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 813-1] wordpress security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-01-05 00:00:00 +0100 (Fri, 05 Jan 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/02/msg00000.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"wordpress on Debian Linux");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
3.6.1+dfsg-1~deb7u13.

We recommend that you upgrade your wordpress packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered in wordpress, a web blogging
tool. The Common Vulnerabilities and Exposures project identifies the
following issues.

CVE-2017-5488

Multiple cross-site scripting (XSS) vulnerabilities in
wp-admin/update-core.php in WordPress before 4.7.1 allow remote
attackers to inject arbitrary web script or HTML via the name or
version header of a plugin.

CVE-2017-5489

Cross-site request forgery (CSRF) vulnerability in WordPress before
4.7.1 allows remote attackers to hijack the authentication of
unspecified victims via vectors involving a Flash file upload.

CVE-2017-5490

Cross-site scripting (XSS) vulnerability in the theme-name fallback
functionality in wp-includes/class-wp-theme.php in WordPress before
4.7.1 allows remote attackers to inject arbitrary web script or HTML
via a crafted directory name of a theme, related to
wp-admin/includes/class-theme-installer-skin.php.

CVE-2017-5491

wp-mail.php in WordPress before 4.7.1 might allow remote attackers to
bypass intended posting restrictions via a spoofed mail server with the
mail.example.com name.

CVE-2017-5492

Cross-site request forgery (CSRF) vulnerability in the widget-editing
accessibility-mode feature in WordPress before 4.7.1 allows remote
attackers to hijack the authentication of unspecified victims for
requests that perform a widgets-access action, related to
wp-admin/includes/class-wp-screen.php and wp-admin/widgets.php.

CVE-2017-5493

wp-includes/ms-functions.php in the Multisite WordPress API in WordPress
before 4.7.1 does not properly choose random numbers for keys, which
makes it easier for remote attackers to bypass intended access
restrictions via a crafted site signup or user signup.

CVE-2017-5610

wp-admin/includes/class-wp-press-this.php in Press This in WordPress
before 4.7.2 does not properly restrict visibility of a
taxonomy-assignment user interface, which allows remote attackers to
bypass intended access restrictions by reading terms.

CVE-2017-5611

SQL injection vulnerability in wp-includes/class-wp-query.php in
WP_Query in WordPress before 4.7.2 allows remote attackers to execute
arbitrary SQL commands by leveraging the presence of an affected
plugin or theme that mishandles a crafted post type name.

CVE-2017-5612

Cross-site scripting (XSS) vulnerability in
wp-admin/includes/class-wp-posts-list-table.php in the posts list
table in WordPress before 4.7.2 allows remote attackers to inject
arbitrary web script or HTML via a crafted excerpt.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"wordpress", ver:"3.6.1+dfsg-1~deb7u13", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.6.1+dfsg-1~deb7u13", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}