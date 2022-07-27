# OpenVAS Vulnerability Test
# $Id: ubuntu_853_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_853_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-853-1 (xulrunner-1.9.1)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
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

include("revisions-lib.inc");
tag_solution = "The problem can be corrected by upgrading your system to the
 following package versions:

Ubuntu 8.04 LTS:
  firefox-3.0                     3.0.15+nobinonly-0ubuntu0.8.04.1
  xulrunner-1.9                   1.9.0.15+nobinonly-0ubuntu0.8.04.1

Ubuntu 8.10:
  abrowser                        3.0.15+nobinonly-0ubuntu0.8.10.1
  firefox-3.0                     3.0.15+nobinonly-0ubuntu0.8.10.1
  xulrunner-1.9                   1.9.0.15+nobinonly-0ubuntu0.8.10.1

Ubuntu 9.04:
  abrowser                        3.0.15+nobinonly-0ubuntu0.9.04.1
  firefox-3.0                     3.0.15+nobinonly-0ubuntu0.9.04.1
  xulrunner-1.9                   1.9.0.15+nobinonly-0ubuntu0.9.04.1

Ubuntu 9.10:
  firefox-3.5                     3.5.4+nobinonly-0ubuntu0.9.10.1
  xulrunner-1.9.1                 1.9.1.4+nobinonly-0ubuntu0.9.10.1

After a standard system upgrade you need to restart Firefox and any
applications that use xulrunner, such as Epiphany, to effect the necessary
changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-853-1";

tag_summary = "The remote host is missing an update to xulrunner-1.9.1
announced via advisory USN-853-1.

A number of security issues affecting xulrunner and Firefox
have been corrected.  For details, please visit the referenced
security advisories.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311622");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-11-23 20:51:51 +0100 (Mon, 23 Nov 2009)");
 script_cve_id("CVE-2009-0689", "CVE-2009-3380", "CVE-2009-3274", "CVE-2009-3381", "CVE-2009-3382", "CVE-2009-3383", "CVE-2009-3371", "CVE-2009-3370", "CVE-2009-3373", "CVE-2009-3372", "CVE-2009-3375", "CVE-2009-3374", "CVE-2009-3377", "CVE-2009-3376");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Ubuntu USN-853-1 (xulrunner-1.9.1)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-853-1/");

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"3.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"3.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dev", ver:"3.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-dev", ver:"3.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-dom-inspector", ver:"3.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-venkman", ver:"3.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"3.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dom-inspector", ver:"3.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso-gnome-support", ver:"3.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso", ver:"3.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-libthai", ver:"3.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-dom-inspector", ver:"3.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-gnome-support", ver:"3.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-venkman", ver:"3.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk", ver:"3.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dom-inspector", ver:"1.9.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-venkman", ver:"1.9.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-dev", ver:"3.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-gnome-support", ver:"3.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dev", ver:"1.9.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.15+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"abrowser", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dev", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-dev", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-dom-inspector", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-venkman", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dom-inspector", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso-gnome-support", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-libthai", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-dom-inspector", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-gnome-support", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-venkman", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dom-inspector", ver:"1.9.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-venkman", ver:"1.9.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"abrowser-3.0-branding", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-branding", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-dev", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-gnome-support", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dev", ver:"1.9.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.0.15+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"abrowser", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dev", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dev", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-dev", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-dom-inspector", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-venkman", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso-dom-inspector", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso-gnome-support", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-granparadiso", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-libthai", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-dom-inspector", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-gnome-support", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk-venkman", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-trunk", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dom-inspector", ver:"1.9.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-venkman", ver:"1.9.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"abrowser-3.0-branding", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-branding", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-dev", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-gnome-support", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dev", ver:"1.9.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.0.15+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"abrowser", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-dev", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.1-dbg", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.1-dev", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"abrowser-3.0-branding", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"abrowser-3.0", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"abrowser-3.1-branding", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"abrowser-3.1", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"abrowser-3.5", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-branding", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-dom-inspector", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-gnome-support", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0-venkman", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.1-branding", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.1-gnome-support", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.1", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"abrowser-3.5-branding", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.5-branding", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.5-dbg", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.5-dev", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.5-gnome-support", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-3.5", ver:"3.5.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9.1-dbg", ver:"1.9.1.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9.1-dev", ver:"1.9.1.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9.1-gnome-support", ver:"1.9.1.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9.1-testsuite-dev", ver:"1.9.1.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9.1", ver:"1.9.1.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.1.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9.1-testsuite", ver:"1.9.1.4+nobinonly-0ubuntu0.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
