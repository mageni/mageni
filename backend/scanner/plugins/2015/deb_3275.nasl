# OpenVAS Vulnerability Test
# $Id: deb_3275.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3275-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703275");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-0850");
  script_name("Debian Security Advisory DSA 3275-1 (fusionforge - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-05-30 00:00:00 +0200 (Sat, 30 May 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3275.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"fusionforge on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie), this problem has been fixed in
version 5.3.2+20141104-3+deb8u1.

For the testing distribution (stretch) and the unstable distribution
(sid), this problem will be fixed soon.

We recommend that you upgrade your fusionforge packages.");
  script_tag(name:"summary", value:"Ansgar Burchardt discovered that the Git plugin for FusionForge, a
web-based project-management and collaboration software, does not
sufficiently validate user provided input as parameter to the method to
create secondary Git repositories. A remote attacker can use this flaw
to execute arbitrary code as root via a specially crafted URL.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"fusionforge-full", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-minimal", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-admssw", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-authcas", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-authhttpd", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-authldap", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-blocks", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-compactpreview", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-contribtracker", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-doaprdf", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-extsubproj", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-foafprofiles", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-globalsearch", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-gravatar", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-headermenu", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-hudson", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-mediawiki", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-message", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-moinmoin", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-projectlabels", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-scmarch", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-scmbzr", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-scmcvs", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-scmdarcs", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-scmgit", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-scmhg", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-scmhook", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-scmsvn", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-plugin-sysauthldap", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fusionforge-standard", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gforge", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gforge-common", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gforge-db-postgresql", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gforge-db-remote", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gforge-dns-bind9", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gforge-ftp-proftpd", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gforge-lists-mailman", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gforge-mta-exim4", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gforge-mta-postfix", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gforge-shell-postgresql", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gforge-web-apache2", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gforge-web-apache2-vhosts", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}