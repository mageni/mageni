# OpenVAS Vulnerability Test
# $Id: ubuntu_789_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_789_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-789-1 (gst-plugins-good0.10)
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

Ubuntu 6.06 LTS:
  gstreamer0.10-plugins-good      0.10.3-0ubuntu4.2

Ubuntu 8.04 LTS:
  gstreamer0.10-plugins-good      0.10.7-3ubuntu0.3

Ubuntu 8.10:
  gstreamer0.10-plugins-good      0.10.10.4-1ubuntu1.2

Ubuntu 9.04:
  gstreamer0.10-plugins-good      0.10.14-1ubuntu0.1

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-789-1";

tag_insight = "Tielei Wang discovered that GStreamer Good Plugins did not correctly handle
malformed PNG image files. If a user were tricked into opening a crafted
PNG image file with a GStreamer application, an attacker could cause a
denial of service via application crash, or possibly execute arbitrary code
with the privileges of the user invoking the program.";
tag_summary = "The remote host is missing an update to gst-plugins-good0.10
announced via advisory USN-789-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311931");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
 script_cve_id("CVE-2009-1932", "CVE-2008-5515", "CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0781", "CVE-2009-0783", "CVE-2009-1440", "CVE-2009-1201", "CVE-2009-1202", "CVE-2009-1203", "CVE-2009-1760", "CVE-2009-1163", "CVE-2009-2045", "CVE-2009-2046", "CVE-2009-0688");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("Ubuntu USN-789-1 (gst-plugins-good0.10)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-789-1/");

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
 script_tag(name : "insight" , value : tag_insight);
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
if ((res = isdpkgvuln(pkg:"gstreamer0.10-plugins-good-doc", ver:"0.10.3-0ubuntu4.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gstreamer0.10-esd", ver:"0.10.3-0ubuntu4.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gstreamer0.10-plugins-good-dbg", ver:"0.10.3-0ubuntu4.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gstreamer0.10-plugins-good", ver:"0.10.3-0ubuntu4.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gstreamer0.10-plugins-good-doc", ver:"0.10.7-3ubuntu0.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gstreamer0.10-esd", ver:"0.10.7-3ubuntu0.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gstreamer0.10-plugins-good-dbg", ver:"0.10.7-3ubuntu0.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gstreamer0.10-plugins-good", ver:"0.10.7-3ubuntu0.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gstreamer0.10-plugins-good-doc", ver:"0.10.10.4-1ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gstreamer0.10-esd", ver:"0.10.10.4-1ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gstreamer0.10-plugins-good-dbg", ver:"0.10.10.4-1ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gstreamer0.10-plugins-good", ver:"0.10.10.4-1ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gstreamer0.10-pulseaudio", ver:"0.10.10.4-1ubuntu1.2", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gstreamer0.10-plugins-good-doc", ver:"0.10.14-1ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gstreamer0.10-esd", ver:"0.10.14-1ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gstreamer0.10-plugins-good-dbg", ver:"0.10.14-1ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gstreamer0.10-plugins-good", ver:"0.10.14-1ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gstreamer0.10-pulseaudio", ver:"0.10.14-1ubuntu0.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"amule-common", ver:"2.2.1-1+lenny2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"amule-utils", ver:"2.2.1-1+lenny2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"amule-utils-gui", ver:"2.2.1-1+lenny2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"amule-daemon", ver:"2.2.1-1+lenny2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"amule", ver:"2.2.1-1+lenny2", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mahara", ver:"1.0.4-4+lenny3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mahara-apache2", ver:"1.0.4-4+lenny3", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-dev", ver:"2.1.19.dfsg1-0.1ubuntu3.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-sql", ver:"2.1.19.dfsg1-0.1ubuntu3.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules", ver:"2.1.19.dfsg1-0.1ubuntu3.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2", ver:"2.1.19.dfsg1-0.1ubuntu3.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sasl2-bin", ver:"2.1.19.dfsg1-0.1ubuntu3.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-heimdal", ver:"2.1.19.dfsg1-0.1ubuntu3.1", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-sasl2-doc", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-sasl2-dbg", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-2", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-dev", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-sql", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sasl2-bin", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-mit", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-ldap", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-otp", ver:"2.1.22.dfsg1-18ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-sasl2-doc", ver:"2.1.22.dfsg1-21ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-sasl2-dbg", ver:"2.1.22.dfsg1-21ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-2", ver:"2.1.22.dfsg1-21ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-dev", ver:"2.1.22.dfsg1-21ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-sql", ver:"2.1.22.dfsg1-21ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules", ver:"2.1.22.dfsg1-21ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sasl2-bin", ver:"2.1.22.dfsg1-21ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-mit", ver:"2.1.22.dfsg1-21ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-ldap", ver:"2.1.22.dfsg1-21ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-otp", ver:"2.1.22.dfsg1-21ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-sasl2-doc", ver:"2.1.22.dfsg1-23ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cyrus-sasl2-dbg", ver:"2.1.22.dfsg1-23ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-2", ver:"2.1.22.dfsg1-23ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-dev", ver:"2.1.22.dfsg1-23ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-sql", ver:"2.1.22.dfsg1-23ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules", ver:"2.1.22.dfsg1-23ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sasl2-bin", ver:"2.1.22.dfsg1-23ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-mit", ver:"2.1.22.dfsg1-23ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-ldap", ver:"2.1.22.dfsg1-23ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsasl2-modules-otp", ver:"2.1.22.dfsg1-23ubuntu3.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
