# OpenVAS Vulnerability Test
# $Id: deb_3750.nasl 6607 2017-07-07 12:04:25Z cfischer $
# Auto-generated from advisory DSA 3750-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net
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
    script_oid("1.3.6.1.4.1.25623.1.0.300000");
    script_version("$Revision: 6607 $");
    script_cve_id("CVE-2016-10033", "CVE-2016-10045");
    script_name("Debian Security Advisory DSA 3750-1 (libphp-phpmailer - security update)");
    script_tag(name: "last_modification", value: "$Date: 2017-07-07 14:04:25 +0200 (Fri, 07 Jul 2017) $");
    script_tag(name: "creation_date", value: "2017-01-05 13:19:04 +0530 (Thu, 05 Jan 2017)");
    script_tag(name:"cvss_base", value:"7.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2016/dsa-3750.html");

    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "libphp-phpmailer on Debian Linux");
    script_tag(name: "insight",   value: "Many PHP developers utilize email in
their code. The only PHP function that supports this is the mail() function.
However, it does not provide any assistance for making use of popular features
such as HTML-based emails and attachments.");
    script_tag(name: "solution",  value: "For the stable distribution (jessie),
this problem has been fixed in version 5.2.9+dfsg-2+deb8u2.

For the unstable distribution (sid), this problem has been fixed in
version 5.2.14+dfsg-2.1.

We recommend that you upgrade your libphp-phpmailer packages.");
    script_tag(name: "summary",   value: "Dawid Golunski discovered that PHPMailer,
a popular library to send email from PHP applications, allowed a remote attacker to
execute code if they were able to provide a crafted Sender address.

Note that for this issue also CVE-2016-10045 was assigned, which is a regression in
the original patch proposed for CVE-2016-10033. Because the origial patch was not
applied in Debian, Debian was not vulnerable to CVE-2016-10045.");
    script_tag(name: "vuldetect", value: "This check tests the installed software
version using the apt package manager.");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libphp-phpmailer", ver:"5.2.9+dfsg-2+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
