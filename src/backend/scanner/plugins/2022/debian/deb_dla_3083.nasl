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
  script_oid("1.3.6.1.4.1.25623.1.0.893083");
  script_version("2022-08-29T08:42:23+0000");
  script_cve_id("CVE-2021-29509", "CVE-2021-41136", "CVE-2022-23634", "CVE-2022-24790");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-08-29 08:42:23 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-24 19:30:00 +0000 (Mon, 24 May 2021)");
  script_tag(name:"creation_date", value:"2022-08-28 01:00:11 +0000 (Sun, 28 Aug 2022)");
  script_name("Debian LTS: Security Advisory for puma (DLA-3083-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/08/msg00015.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3083-1");
  script_xref(name:"Advisory-ID", value:"DLA-3083-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'puma'
  package(s) announced via the DLA-3083-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in puma, a web server for
ruby/rack applications.

CVE-2021-29509

Keepalive Connections Causing Denial Of Service in puma.

CVE-2021-41136

puma with a proxy which forwards HTTP header values which contain
the LF character could allow HTTP request smugggling. A client
could smuggle a request through a proxy, causing the proxy to send
a response back to another unknown client.

CVE-2022-23634

puma may not always call `close` on the response body. Rails,
prior to version `7.0.2.2`, depended on the response body being
closed in order for its `CurrentAttributes` implementation to work
correctly. The combination of these two behaviors (Puma not
closing the body + Rails' Executor implementation) causes
information leakage.

CVE-2022-24790

using Puma behind a proxy that does not properly validate that the
incoming HTTP request matches the RFC7230 standard, Puma and the
frontend proxy may disagree on where a request starts and ends.
This would allow requests to be smuggled via the front-end proxy
to Puma");

  script_tag(name:"affected", value:"'puma' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
3.12.0-2+deb10u3.

We recommend that you upgrade your puma packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"puma", ver:"3.12.0-2+deb10u3", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
