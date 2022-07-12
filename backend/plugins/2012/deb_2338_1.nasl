# OpenVAS Vulnerability Test
# $Id: deb_2338_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2338-1 (moodle)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70552");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-11 02:27:54 -0500 (Sat, 11 Feb 2012)");
  script_name("Debian Security Advisory DSA 2338-1 (moodle)");
  script_cve_id("CVE-2011-4294", "CVE-2011-4301", "CVE-2011-4302", "CVE-2011-4305", "CVE-2011-4306");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202338-1");
  script_tag(name:"insight", value:"Several cross-site scripting and information disclosure issues have
been fixed in Moodle, a course management system for online learning:

  * MSA-11-0020 Continue links in error messages can lead offsite

  * MSA-11-0024 Recaptcha images were being authenticated from an older
server

  * MSA-11-0025 Group names in user upload CSV not escaped

  * MSA-11-0026 Fields in user upload CSV not escaped

  * MSA-11-0031 Forms API constant issue

  * MSA-11-0032 MNET SSL validation issue

  * MSA-11-0036 Messaging refresh vulnerability

  * MSA-11-0037 Course section editing injection vulnerability

  * MSA-11-0038 Database injection protection strengthened

For the stable distribution (squeeze), this problem has been fixed in
version 1.9.9.dfsg2-2.1+squeeze2.

For the unstable distribution (sid), this problem has been fixed in
version 1.9.9.dfsg2-4.");

  script_tag(name:"solution", value:"We recommend that you upgrade your moodle packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to moodle
announced via advisory DSA 2338-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"moodle", ver:"1.9.9.dfsg2-2.1+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}