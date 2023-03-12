# Copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2014.65");
  script_cve_id("CVE-2014-0480", "CVE-2014-0481", "CVE-2014-0482", "CVE-2014-0483");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DLA-65)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-65");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2014/dla-65");
  script_xref(name:"URL", value:"http://www.freexian.com/services/debian-lts.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-django' package(s) announced via the DLA-65 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update address an issue with reverse() generating external URLs, a denial of service involving file uploads, a potential session hijacking issue in the remote-user middleware, and a data leak in the administrative interface.

This update has been brought to you thanks to the Debian LTS sponsors: [link moved to references]

CVE-2014-0480

Django includes the helper function django.core.urlresolvers.reverse, typically used to generate a URL from a reference to a view function or URL pattern name. However, when presented with input beginning with two forward-slash characters (//), reverse() could generate scheme-relative URLs to other hosts, allowing an attacker who is aware of unsafe use of reverse() (i.e., in a situation where an end user can control the target of a redirect, to take a common example) to generate links to sites of their choice, enabling phishing and other attacks.

To remedy this, URL reversing now ensures that no URL starts with two slashes (//), replacing the second slash with its URL encoded counterpart (%2F). This approach ensures that semantics stay the same, while making the URL relative to the domain and not to the scheme.

CVE-2014-0481

In the default configuration, when Django's file upload handling system is presented with a file that would have the same on-disk path and name as an existing file, it attempts to generate a new unique filename by appending an underscore and an integer to the end of the (as stored on disk) filename, incrementing the integer (i.e., _1, _2, etc.) until it has generated a name which does not conflict with any existing file.

An attacker with knowledge of this can exploit the sequential behavior of filename generation by uploading many tiny files which all share a filename, Django will, in processing them, generate ever-increasing numbers of os.stat() calls as it attempts to generate a unique filename. As a result, even a relatively small number of such uploads can significantly degrade performance.

To remedy this, Django's file-upload system will no longer use sequential integer names to avoid filename conflicts on disk, instead, a short random alphanumeric string will be appended, removing the ability to reliably generate many repeatedly-conflicting filenames.

CVE-2014-0482

Django provides a middleware django.contrib.auth.middleware.RemoteUserMiddleware -- and an authentication backend, django.contrib.auth.backends.RemoteUserBackend, which use the REMOTE_USER header for authentication purposes.

In some circumstances, use of this middleware and backend could result in one user receiving another user's session, if a change to the REMOTE_USER header occurred without corresponding logout/login actions.

To remedy this, the middleware will now ensure that a change to REMOTE_USER without an explicit logout will force a logout and subsequent login prior to accepting the new REMOTE_USER.

CVE-2014-0483

Django's ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'python-django' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"python-django-doc", ver:"1.2.3-3+squeeze11", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.2.3-3+squeeze11", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
