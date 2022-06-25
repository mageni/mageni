# OpenVAS Vulnerability Test
# $Id: deb_2332_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2332-1 (python-django)
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
  script_oid("1.3.6.1.4.1.25623.1.0.70548");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-4136", "CVE-2011-4137", "CVE-2011-4138", "CVE-2011-4139", "CVE-2011-4140");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-11 02:27:22 -0500 (Sat, 11 Feb 2012)");
  script_name("Debian Security Advisory DSA 2332-1 (python-django)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202332-1");
  script_tag(name:"insight", value:"Paul McMillan, Mozilla and the Django core team discovered several
vulnerabilities in Django, a Python web framework:

CVE-2011-4136

When using memory-based sessions and caching, Django sessions are
stored directly in the root namespace of the cache. When user data is
stored in the same cache, a remote user may take over a session.

CVE-2011-4137, CVE-2011-4138

Django's field type URLfield by default checks supplied URL's by
issuing a request to it, which doesn't time out. A Denial of Service
is possible by supplying specially prepared URL's that keep the
connection open indefinitely or fill the Django's server memory.

CVE-2011-4139

Django used X-Forwarded-Host headers to construct full URL's. This
header may not contain trusted input and could be used to poison the
cache.

CVE-2011-4140

The CSRF protection mechanism in Django does not properly handle
web-server configurations supporting arbitrary HTTP Host headers,
which allows remote attackers to trigger unauthenticated forged
requests.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.0.2-1+lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 1.2.3-3+squeeze2.

For the testing (wheezy) and unstable distribution (sid), this problem
has been fixed in version 1.3.1-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your python-django packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to python-django
announced via advisory DSA 2332-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"python-django", ver:"1.0.2-1+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-django", ver:"1.2.3-3+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-django-doc", ver:"1.2.3-3+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}