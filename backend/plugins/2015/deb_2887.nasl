# OpenVAS Vulnerability Test
# $Id: deb_2887.nasl 6609 2017-07-07 12:05:59Z cfischer $
# Auto-generated from advisory DSA 2887-1 using nvtgen 1.0
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
    script_oid("1.3.6.1.4.1.25623.1.0.300023");
    script_version("$Revision: 6609 $");
    script_cve_id("CVE-2013-4389");
    script_name("Debian Security Advisory DSA 2887-1 (ruby-actionmailer-3.2 - security update)");
    script_tag(name: "last_modification", value: "$Date: 2017-07-07 14:05:59 +0200 (Fri, 07 Jul 2017) $");
    script_tag(name: "creation_date", value: "2014-03-27 00:00:00 +0100 (Thu, 27 Mar 2014)");
    script_tag(name: "cvss_base", value: "4.3");
    script_tag(name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P");
    script_tag(name: "solution_type", value: "VendorFix");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-2887.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "ruby-actionmailer-3.2 on Debian Linux");
    script_tag(name: "insight",   value: "Action Mailer is a framework for
working with email on Rails. Compose, deliver, receive, and test emails using
the familiar controller/view pattern. First-class support for multipart email
and attachments.");
    script_tag(name: "solution",  value: "For the stable distribution (wheezy),
this problem has been fixed in version 3.2.6-2+deb7u1. ruby-activesupport-3.2 was
updated in a related change to version 3.2.6-6+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 3.2.16-3+0 of the rails-3.2 source package.

We recommend that you upgrade your ruby-actionmailer-3.2 packages.");
    script_tag(name: "summary",   value: "Aaron Neyer discovered that missing
input sanitising in the logging component of Ruby Actionmailer could result in
denial of service through a malformed e-mail message.");
    script_tag(name: "vuldetect", value: "This check tests the installed software version using the apt package manager.");
    script_tag(name:"qod_type", value:"package");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"ruby-actionmailer-3.2", ver:"3.2.6-2+deb7u1", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
