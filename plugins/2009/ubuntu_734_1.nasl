# OpenVAS Vulnerability Test
# $Id: ubuntu_734_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_734_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-734-1 (ffmpeg-debian)
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

Ubuntu 7.10:
  libavcodec1d                    3:0.cvs20070307-5ubuntu4.2
  libavformat1d                   3:0.cvs20070307-5ubuntu4.2

Ubuntu 8.04 LTS:
  libavcodec1d                    3:0.cvs20070307-5ubuntu7.3
  libavformat1d                   3:0.cvs20070307-5ubuntu7.3

Ubuntu 8.10:
  libavcodec51                    3:0.svn20080206-12ubuntu3.1
  libavformat52                   3:0.svn20080206-12ubuntu3.1

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-734-1";

tag_insight = "It was discovered that FFmpeg did not correctly handle certain malformed
Ogg Media (OGM) files. If a user were tricked into opening a crafted Ogg
Media file, an attacker could cause the application using FFmpeg to crash,
leading to a denial of service. (CVE-2008-4610)

It was discovered that FFmpeg did not correctly handle certain parameters
when creating DTS streams. If a user were tricked into processing certain
commands, an attacker could cause a denial of service via application
crash, or possibly execute arbitrary code with the privileges of the user
invoking the program. This issue only affected Ubuntu 8.10. (CVE-2008-4866)

It was discovered that FFmpeg did not correctly handle certain malformed
DTS Coherent Acoustics (DCA) files. If a user were tricked into opening a
crafted DCA file, an attacker could cause a denial of service via
application crash, or possibly execute arbitrary code with the privileges
of the user invoking the program. (CVE-2008-4867)

It was discovered that FFmpeg did not correctly handle certain malformed 4X
movie (4xm) files. If a user were tricked into opening a crafted 4xm file,
an attacker could execute arbitrary code with the privileges of the user
invoking the program. (CVE-2009-0385)";
tag_summary = "The remote host is missing an update to ffmpeg-debian
announced via advisory USN-734-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311227");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-03-20 00:52:38 +0100 (Fri, 20 Mar 2009)");
 script_cve_id("CVE-2008-4610", "CVE-2008-4866", "CVE-2008-4867", "CVE-2009-0385", "CVE-2009-0587", "CVE-2008-4316");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Ubuntu USN-734-1 (ffmpeg-debian)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-734-1/");

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
if ((res = isdpkgvuln(pkg:"libavcodec-dev", ver:"0.cvs20070307-5ubuntu4.2", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavcodec1d", ver:"0.cvs20070307-5ubuntu4.2", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavformat-dev", ver:"0.cvs20070307-5ubuntu4.2", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavformat1d", ver:"0.cvs20070307-5ubuntu4.2", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavutil-dev", ver:"0.cvs20070307-5ubuntu4.2", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavutil1d", ver:"0.cvs20070307-5ubuntu4.2", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpostproc-dev", ver:"0.cvs20070307-5ubuntu4.2", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpostproc1d", ver:"0.cvs20070307-5ubuntu4.2", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libswscale-dev", ver:"0.cvs20070307-5ubuntu4.2", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libswscale1d", ver:"0.cvs20070307-5ubuntu4.2", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ffmpeg", ver:"0.cvs20070307-5ubuntu4.2", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavcodec-dev", ver:"0.cvs20070307-5ubuntu7.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavcodec1d", ver:"0.cvs20070307-5ubuntu7.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavformat-dev", ver:"0.cvs20070307-5ubuntu7.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavformat1d", ver:"0.cvs20070307-5ubuntu7.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavutil-dev", ver:"0.cvs20070307-5ubuntu7.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavutil1d", ver:"0.cvs20070307-5ubuntu7.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpostproc-dev", ver:"0.cvs20070307-5ubuntu7.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpostproc1d", ver:"0.cvs20070307-5ubuntu7.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libswscale-dev", ver:"0.cvs20070307-5ubuntu7.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libswscale1d", ver:"0.cvs20070307-5ubuntu7.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ffmpeg", ver:"0.cvs20070307-5ubuntu7.3", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ffmpeg-doc", ver:"0.svn20080206-12ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ffmpeg-dbg", ver:"0.svn20080206-12ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ffmpeg", ver:"0.svn20080206-12ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavcodec-dev", ver:"0.svn20080206-12ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavcodec51", ver:"0.svn20080206-12ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavdevice-dev", ver:"0.svn20080206-12ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavdevice52", ver:"0.svn20080206-12ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavformat-dev", ver:"0.svn20080206-12ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavformat52", ver:"0.svn20080206-12ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavutil-dev", ver:"0.svn20080206-12ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavutil49", ver:"0.svn20080206-12ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpostproc-dev", ver:"0.svn20080206-12ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpostproc51", ver:"0.svn20080206-12ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libswscale-dev", ver:"0.svn20080206-12ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libswscale0", ver:"0.svn20080206-12ubuntu3.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"evolution-data-server-dbg", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"evolution-data-server-dev", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"evolution-data-server", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcamel1.2-8", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcamel1.2-dev", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libebook1.2-5", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libebook1.2-dev", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecal1.2-3", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecal1.2-dev", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedata-book1.2-2", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedata-book1.2-dev", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedata-cal1.2-1", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedata-cal1.2-dev", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedataserver1.2-7", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedataserver1.2-dev", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedataserverui1.2-6", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedataserverui1.2-dev", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libegroupwise1.2-9", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libegroupwise1.2-dev", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libexchange-storage1.2-1", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libexchange-storage1.2-dev", ver:"1.6.1-0ubuntu7.2", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"evolution-data-server-common", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"evolution-data-server-dbg", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"evolution-data-server-dev", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"evolution-data-server", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcamel1.2-10", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcamel1.2-dev", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libebook1.2-9", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libebook1.2-dev", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecal1.2-7", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libecal1.2-dev", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedata-book1.2-2", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedata-book1.2-dev", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedata-cal1.2-6", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedata-cal1.2-dev", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedataserver1.2-9", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedataserver1.2-dev", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedataserverui1.2-8", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libedataserverui1.2-dev", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libegroupwise1.2-13", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libegroupwise1.2-dev", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libexchange-storage1.2-3", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libexchange-storage1.2-dev", ver:"1.12.1-0ubuntu2.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-data", ver:"2.14.1-1ubuntu1.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-doc", ver:"2.14.1-1ubuntu1.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-0-dbg", ver:"2.14.1-1ubuntu1.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-0", ver:"2.14.1-1ubuntu1.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-dev", ver:"2.14.1-1ubuntu1.1", rls:"UBUNTU7.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-doc", ver:"2.16.6-0ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-data", ver:"2.16.6-0ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-0-dbg", ver:"2.16.6-0ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-0", ver:"2.16.6-0ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-dev", ver:"2.16.6-0ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgio-fam", ver:"2.16.6-0ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-data", ver:"2.18.2-0ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-doc", ver:"2.18.2-0ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-0-dbg", ver:"2.18.2-0ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-0", ver:"2.18.2-0ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libglib2.0-dev", ver:"2.18.2-0ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgio-fam", ver:"2.18.2-0ubuntu2.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
