# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 3010-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.703010");
  script_version("2021-11-23T15:20:34+0000");
  script_cve_id("CVE-2014-0480", "CVE-2014-0481", "CVE-2014-0482", "CVE-2014-0483");
  script_name("Debian Security Advisory DSA 3010-1 (python-django - security update)");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2014-08-22 00:00:00 +0200 (Fri, 22 Aug 2014)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-3010.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"python-django on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 1.4.5-1+deb7u8.

For the unstable distribution (sid), these problems have been fixed in
version 1.6.6-1.

We recommend that you upgrade your python-django packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered in Django, a high-level Python
web development framework. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2014-0480
Florian Apolloner discovered that in certain situations, URL
reversing could generate scheme-relative URLs which could
unexpectedly redirect a user to a different host, leading to
phishing attacks.

CVE-2014-0481
David Wilson reported a file upload denial of service vulnerability.
Django's file upload handling in its default configuration may
degrade to producing a huge number of `os.stat()` system calls when
a duplicate filename is uploaded. A remote attacker with the ability
to upload files can cause poor performance in the upload handler,
eventually causing it to become very slow.

CVE-2014-0482
David Greisen discovered that under some circumstances, the use of
the RemoteUserMiddleware middleware and the RemoteUserBackend
authentication backend could result in one user receiving another
user's session, if a change to the REMOTE_USER header occurred
without corresponding logout/login actions.

CVE-2014-0483Collin Anderson discovered that it is possible to reveal any field's
data by modifying the popup and to_field
parameters of the query
string on an admin change form page. A user with access to the admin
interface, and with sufficient knowledge of model structure and the
appropriate URLs, could construct popup views which would display
the values of non-relationship fields, including fields the
application developer had not intended to expose in such a fashion.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"python-django", ver:"1.4.5-1+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-django-doc", ver:"1.4.5-1+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}