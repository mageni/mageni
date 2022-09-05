# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.893093");
  script_version("2022-09-05T08:41:13+0000");
  script_cve_id("CVE-2022-21831", "CVE-2022-22577", "CVE-2022-23633", "CVE-2022-27777", "CVE-2022-32224");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-09-05 08:41:13 +0000 (Mon, 05 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-07 14:57:00 +0000 (Tue, 07 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-09-04 01:00:09 +0000 (Sun, 04 Sep 2022)");
  script_name("Debian LTS: Security Advisory for rails (DLA-3093-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/09/msg00002.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3093-1");
  script_xref(name:"Advisory-ID", value:"DLA-3093-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rails'
  package(s) announced via the DLA-3093-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities have been discovered in rails, a ruby
based MVC frame work for web development.

CVE-2022-21831

A code injection vulnerability exists in the Active Storage that
could allow an attacker to execute code via image_processing
arguments.

CVE-2022-22577

An XSS Vulnerability in Action Pack that could allow an attacker
to bypass CSP for non HTML like responses.

CVE-2022-23633

Action Pack is a framework for handling and responding to web
requests. Under certain circumstances response bodies will not be
closed. In the event a response is *not* notified of a `close`,
`ActionDispatch::Executor` will not know to reset thread local
state for the next request. This can lead to data being leaked to
subsequent requests.

CVE-2022-27777

A XSS Vulnerability in Action View tag helpers which would allow
an attacker to inject content if able to control input into
specific attributes.

CVE-2022-32224

When serialized columns that use YAML (the default) are
deserialized, Rails uses YAML.unsafe_load to convert the YAML data
in to Ruby objects. If an attacker can manipulate data in the
database (via means like SQL injection), then it may be possible
for the attacker to escalate to an RCE.");

  script_tag(name:"affected", value:"'rails' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
2:5.2.2.1+dfsg-1+deb10u4.

We recommend that you upgrade your rails packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"rails", ver:"2:5.2.2.1+dfsg-1+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-actioncable", ver:"2:5.2.2.1+dfsg-1+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-actionmailer", ver:"2:5.2.2.1+dfsg-1+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-actionpack", ver:"2:5.2.2.1+dfsg-1+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-actionview", ver:"2:5.2.2.1+dfsg-1+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-activejob", ver:"2:5.2.2.1+dfsg-1+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-activemodel", ver:"2:5.2.2.1+dfsg-1+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-activerecord", ver:"2:5.2.2.1+dfsg-1+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-activestorage", ver:"2:5.2.2.1+dfsg-1+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-activesupport", ver:"2:5.2.2.1+dfsg-1+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-rails", ver:"2:5.2.2.1+dfsg-1+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-railties", ver:"2:5.2.2.1+dfsg-1+deb10u4", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
