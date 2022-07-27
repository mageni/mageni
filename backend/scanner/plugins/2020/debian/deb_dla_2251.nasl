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
  script_oid("1.3.6.1.4.1.25623.1.0.892251");
  script_version("2020-06-20T03:00:10+0000");
  script_cve_id("CVE-2020-8164", "CVE-2020-8165");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-06-22 10:35:23 +0000 (Mon, 22 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-20 03:00:10 +0000 (Sat, 20 Jun 2020)");
  script_name("Debian LTS: Security Advisory for rails (DLA-2251-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/06/msg00022.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2251-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rails'
  package(s) announced via the DLA-2251-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were found in Ruby on Rails, a MVC ruby-based
framework geared for web application development, which could lead to
remote code execution and untrusted user input usage, depending on the
application.

CVE-2020-8164

Strong parameters bypass vector in ActionPack. In some cases user
supplied information can be inadvertently leaked from Strong
Parameters. Specifically the return value of `each`, or
`each_value`, or `each_pair` will return the underlying
'untrusted' hash of data that was read from the parameters.
Applications that use this return value may be inadvertently use
untrusted user input.

CVE-2020-8165

Potentially unintended unmarshalling of user-provided objects in
MemCacheStore. There is potentially unexpected behaviour in the
MemCacheStore where, when untrusted user input is written to the
cache store using the `raw: true` parameter, re-reading the result
from the cache can evaluate the user input as a Marshalled object
instead of plain text. Unmarshalling of untrusted user input can
have impact up to and including RCE. At a minimum, this
vulnerability allows an attacker to inject untrusted Ruby objects
into a web application.

In addition to upgrading to the latest versions of Rails,
developers should ensure that whenever they are calling
`Rails.cache.fetch` they are using consistent values of the `raw`
parameter for both reading and writing.");

  script_tag(name:"affected", value:"'rails' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
2:4.1.8-1+deb8u7.

We recommend that you upgrade your rails packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"rails", ver:"2:4.1.8-1+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-actionmailer", ver:"2:4.1.8-1+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-actionpack", ver:"2:4.1.8-1+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-actionview", ver:"2:4.1.8-1+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-activemodel", ver:"2:4.1.8-1+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-activerecord", ver:"2:4.1.8-1+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-activesupport", ver:"2:4.1.8-1+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-activesupport-2.3", ver:"2:4.1.8-1+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-rails", ver:"2:4.1.8-1+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-railties", ver:"2:4.1.8-1+deb8u7", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
