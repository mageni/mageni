# OpenVAS Vulnerability Test
# $Id: deb_3383.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3383-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703383");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-2213", "CVE-2015-5622", "CVE-2015-5714", "CVE-2015-5715",
                  "CVE-2015-5731", "CVE-2015-5732", "CVE-2015-5734", "CVE-2015-7989");
  script_name("Debian Security Advisory DSA 3383-1 (wordpress - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-10-29 00:00:00 +0100 (Thu, 29 Oct 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3383.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"wordpress on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
these problems have been fixed in version 3.6.1+dfsg-1~deb7u8.

For the stable distribution (jessie), these problems have been fixed
in version 4.1+dfsg-1+deb8u5 or earlier in DSA-3332-1 and DSA-3375-1.

For the testing distribution (stretch), these problems have been fixed
in version 4.3.1+dfsg-1 or earlier versions.

For the unstable distribution (sid), these problems have been fixed in
version 4.3.1+dfsg-1 or earlier versions.

We recommend that you upgrade your wordpress packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were
discovered in Wordpress, a web blogging tool. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2015-2213
SQL Injection allowed a remote attacker to compromise the site.

CVE-2015-5622
The robustness of the shortcodes HTML tags filter has been improved.
The parsing is a bit more strict, which may affect your
installation.

CVE-2015-5714
A cross-site scripting vulnerability when processing shortcode tags.

CVE-2015-5715
A vulnerability has been discovered, allowing users without proper
permissions to publish private posts and make them sticky.

CVE-2015-5731
An attacker could lock a post that was being edited.

CVE-2015-5732
Cross-site scripting in a widget title allows an attacker to steal
sensitive information.

CVE-2015-5734
Fix some broken links in the legacy theme preview.

CVE-2015-7989
A cross-site scripting vulnerability in user list tables.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"wordpress", ver:"3.6.1+dfsg-1~deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.6.1+dfsg-1~deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}