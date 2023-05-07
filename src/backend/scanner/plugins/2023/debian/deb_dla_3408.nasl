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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3408");
  script_cve_id("CVE-2017-17742", "CVE-2019-16201", "CVE-2019-16254", "CVE-2019-16255", "CVE-2020-25613", "CVE-2021-31810", "CVE-2021-32066", "CVE-2023-28755", "CVE-2023-28756");
  script_tag(name:"creation_date", value:"2023-05-01 04:27:16 +0000 (Mon, 01 May 2023)");
  script_version("2023-05-04T09:51:03+0000");
  script_tag(name:"last_modification", value:"2023-05-04 09:51:03 +0000 (Thu, 04 May 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Debian: Security Advisory (DLA-3408)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3408");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3408");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/jruby");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jruby' package(s) announced via the DLA-3408 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were fixed in JRuby, a Java implementation of the Ruby programming language.

CVE-2017-17742

CVE-2019-16254

HTTP Response Splitting attacks in the HTTP server of WEBrick.

CVE-2019-16201

Regular Expression Denial of Service vulnerability of WEBrick's Digest access authentication.

CVE-2019-16255

Code injection vulnerability.

CVE-2020-25613

HTTP Request Smuggling attack in WEBrick.

CVE-2021-31810

Trusting FTP PASV responses vulnerability in Net::FTP.

CVE-2021-32066

Net::IMAP did not raise an exception when StartTLS fails with an an unknown response.

CVE-2023-28755

Quadratic backtracking on invalid URI.

CVE-2023-28756

The Time parser mishandled invalid strings that have specific characters.

For Debian 10 buster, these problems have been fixed in version 9.1.17.0-3+deb10u1.

We recommend that you upgrade your jruby packages.

For the detailed security status of jruby please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'jruby' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"jruby", ver:"9.1.17.0-3+deb10u1", rls:"DEB10"))) {
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
