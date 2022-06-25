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
  script_oid("1.3.6.1.4.1.25623.1.0.892813");
  script_version("2021-11-15T09:54:42+0000");
  script_cve_id("CVE-2021-33829", "CVE-2021-37695");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-10 20:14:00 +0000 (Thu, 10 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-11-10 02:00:12 +0000 (Wed, 10 Nov 2021)");
  script_name("Debian LTS: Security Advisory for ckeditor (DLA-2813-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/11/msg00007.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2813-1");
  script_xref(name:"Advisory-ID", value:"DLA-2813-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/992290");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ckeditor'
  package(s) announced via the DLA-2813-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CKEditor, an open source WYSIWYG HTML editor with rich content
support, which can be embedded into web pages, had two
vulnerabilities as follows:

CVE-2021-33829

A cross-site scripting (XSS) vulnerability in the HTML Data
Processor in CKEditor 4 allows remote attackers to inject
executable JavaScript code through a crafted comment because --!> is mishandled.

CVE-2021-37695

A potential vulnerability has been discovered in CKEditor 4
Fake Objects package. The vulnerability allowed to inject
malformed Fake Objects HTML, which could result in executing
JavaScript code.");

  script_tag(name:"affected", value:"'ckeditor' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
4.5.7+dfsg-2+deb9u1.

We recommend that you upgrade your ckeditor packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"ckeditor", ver:"4.5.7+dfsg-2+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
