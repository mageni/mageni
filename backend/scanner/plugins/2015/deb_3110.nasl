# OpenVAS Vulnerability Test
# $Id: deb_3110.nasl 6609 2017-07-07 12:05:59Z cfischer $
# Auto-generated from advisory DSA 3110-1 using nvtgen 1.0
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
    script_oid("1.3.6.1.4.1.25623.1.0.300024");
    script_version("$Revision: 6609 $");
    script_cve_id("CVE-2014-9475");
    script_name("Debian Security Advisory DSA 3110-1 (mediawiki - security update)");
    script_tag(name: "last_modification", value: "$Date: 2017-07-07 14:05:59 +0200 (Fri, 07 Jul 2017) $");
    script_tag(name: "creation_date", value: "2014-12-23 00:00:00 +0100 (Tue, 23 Dec 2014)");
    script_tag(name:"cvss_base", value:"3.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
    script_tag(name: "solution_type", value: "VendorFix");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-3110.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "mediawiki on Debian Linux");
    script_tag(name: "insight",   value: "MediaWiki is a wiki engine
(a program for creating a collaboratively edited website). It is designed
to handle heavy websites containing library-like document collections, and
supports user uploads of images/sounds, multilingual content, TOC autogeneration,
ISBN links, etc.");
    script_tag(name: "solution",  value: "For the stable distribution (wheezy),
this problem has been fixed in version 1.19.20+dfsg-0+deb7u3; this version
additionally fixes a regression introduced in the previous release, DSA-3100-1.

For the upcoming stable distribution (jessie) and unstable
distribution (sid), this problem has been fixed in version
1:1.19.20+dfsg-2.2.

We recommend that you upgrade your mediawiki packages.");
    script_tag(name: "summary",   value: "A flaw was discovered in mediawiki, a
wiki engine: thumb.php outputs wikitext messages as raw HTML, potentially
leading to cross-site scripting (XSS).");
    script_tag(name: "vuldetect", value: "This check tests the installed software
version using the apt package manager.");
    script_tag(name:"qod_type", value:"package");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"mediawiki", ver:"1.19.20+dfsg-0+deb7u3", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
