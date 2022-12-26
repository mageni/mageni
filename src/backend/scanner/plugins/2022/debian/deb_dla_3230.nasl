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
  script_oid("1.3.6.1.4.1.25623.1.0.893230");
  script_version("2022-12-09T10:11:04+0000");
  script_cve_id("CVE-2021-41182", "CVE-2021-41183", "CVE-2021-41184", "CVE-2022-31160");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-12-09 10:11:04 +0000 (Fri, 09 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-29 18:22:00 +0000 (Fri, 29 Oct 2021)");
  script_tag(name:"creation_date", value:"2022-12-08 02:00:13 +0000 (Thu, 08 Dec 2022)");
  script_name("Debian LTS: Security Advisory for jqueryui (DLA-3230-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/12/msg00015.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3230-1");
  script_xref(name:"Advisory-ID", value:"DLA-3230-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1015982");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jqueryui'
  package(s) announced via the DLA-3230-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"jQuery-UI, the official jQuery user interface library, is a curated set
of user interface interactions, effects, widgets, and themes built on top
of jQuery were reported to have the following vulnerabilities.

CVE-2021-41182

jQuery-UI was accepting the value of the `altField` option of the
Datepicker widget from untrusted sources may execute untrusted code.
This has been fixed and now any string value passed to the `altField`
option is now treated as a CSS selector.

CVE-2021-41183

jQuery-UI was accepting the value of various `*Text` options of the
Datepicker widget from untrusted sources may execute untrusted code.
This has been fixed and now the values passed to various `*Text`
options are now always treated as pure text, not HTML.

CVE-2021-41184

jQuery-UI was accepting the value of the `of` option of the
`.position()` util from untrusted sources may execute untrusted code.
This has been fixed and now any string value passed to the `of`
option is now treated as a CSS selector.

CVE-2022-31160

jQuery-UI was potentially vulnerable to cross-site scripting.
Initializing a checkboxradio widget on an input enclosed within a
label makes that parent label contents considered as the input label.
Calling `.checkboxradio( 'refresh' )` on such a widget and the initial
HTML contained encoded HTML entities will make them erroneously get
decoded. This can lead to potentially executing JavaScript code.");

  script_tag(name:"affected", value:"'jqueryui' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
1.12.1+dfsg-5+deb10u1.

We recommend that you upgrade your jqueryui packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libjs-jquery-ui", ver:"1.12.1+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjs-jquery-ui-docs", ver:"1.12.1+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"node-jquery-ui", ver:"1.12.1+dfsg-5+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
