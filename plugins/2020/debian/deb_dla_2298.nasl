# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892298");
  script_version("2020-07-30T03:00:18+0000");
  script_cve_id("CVE-2019-1010247", "CVE-2019-14857", "CVE-2019-20479");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-07-30 10:23:02 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-30 03:00:18 +0000 (Thu, 30 Jul 2020)");
  script_name("Debian LTS: Security Advisory for libapache2-mod-auth-openidc (DLA-2298-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00028.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2298-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libapache2-mod-auth-openidc'
  package(s) announced via the DLA-2298-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been found in libapache2-mod-auth-openidc, the OpenID
Connect authentication module for the Apache HTTP server.

CVE-2019-14857

Insufficient validation of URLs leads to an Open Redirect
vulnerability. An attacker may trick a victim into providing
credentials for an OpenID provider by forwarding the request to an
illegitimate website.

CVE-2019-20479

Due to insufficient validatation of URLs an Open Redirect
vulnerability for URLs beginning with a slash and backslash could be
abused.

CVE-2019-1010247

The OIDCRedirectURI page contains generated JavaScript code that uses
a poll parameter as a string variable, thus might contain additional
JavaScript code. This might result in Criss-Site Scripting (XSS).");

  script_tag(name:"affected", value:"'libapache2-mod-auth-openidc' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2.1.6-1+deb9u1.

We recommend that you upgrade your libapache2-mod-auth-openidc packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-auth-openidc", ver:"2.1.6-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
