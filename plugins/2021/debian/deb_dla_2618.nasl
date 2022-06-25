# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892618");
  script_version("2021-04-06T03:00:10+0000");
  script_cve_id("CVE-2018-13982", "CVE-2021-26119", "CVE-2021-26120");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-06 10:08:15 +0000 (Tue, 06 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-06 03:00:10 +0000 (Tue, 06 Apr 2021)");
  script_name("Debian LTS: Security Advisory for smarty3 (DLA-2618-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00004.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2618-1");
  script_xref(name:"Advisory-ID", value:"DLA-2618-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'smarty3'
  package(s) announced via the DLA-2618-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in smarty3, a template engine
for PHP.

CVE-2018-13982

path traversal vulnerability due to insufficient sanitization of
code in Smarty templates. This allows attackers controlling the
Smarty template to bypass the trusted directory security
restriction and read arbitrary files.

CVE-2021-26119

allows a Sandbox Escape because $smarty.template_object can be
accessed in sandbox mode.

CVE-2021-26120

allows code injection vulnerability via an unexpected function
name after a {function name= substring.");

  script_tag(name:"affected", value:"'smarty3' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
3.1.31+20161214.1.c7d42e4+selfpack1-2+deb9u2.

We recommend that you upgrade your smarty3 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"smarty3", ver:"3.1.31+20161214.1.c7d42e4+selfpack1-2+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
