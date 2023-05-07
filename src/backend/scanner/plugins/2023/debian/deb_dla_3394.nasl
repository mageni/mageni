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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3394");
  script_cve_id("CVE-2023-27585");
  script_tag(name:"creation_date", value:"2023-04-24 04:22:53 +0000 (Mon, 24 Apr 2023)");
  script_version("2023-04-24T10:19:26+0000");
  script_tag(name:"last_modification", value:"2023-04-24 10:19:26 +0000 (Mon, 24 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-24 15:31:00 +0000 (Fri, 24 Mar 2023)");

  script_name("Debian: Security Advisory (DLA-3394)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3394");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3394");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/asterisk");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'asterisk' package(s) announced via the DLA-3394 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in Asterisk, an Open Source Private Branch Exchange. A buffer overflow vulnerability affects users that use PJSIP DNS resolver. This vulnerability is related to CVE-2022-24793. The difference is that this issue is in parsing the query record `parse_query()`, while the issue in CVE-2022-24793 is in `parse_rr()`. A workaround is to disable DNS resolution in PJSIP config (by setting `nameserver_count` to zero) or use an external resolver implementation instead.

For Debian 10 buster, this problem has been fixed in version 1:16.28.0~dfsg-0+deb10u3.

We recommend that you upgrade your asterisk packages.

For the detailed security status of asterisk please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'asterisk' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-config", ver:"1:16.28.0~dfsg-0+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-dahdi", ver:"1:16.28.0~dfsg-0+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:16.28.0~dfsg-0+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:16.28.0~dfsg-0+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-mobile", ver:"1:16.28.0~dfsg-0+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-modules", ver:"1:16.28.0~dfsg-0+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-mp3", ver:"1:16.28.0~dfsg-0+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-mysql", ver:"1:16.28.0~dfsg-0+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-ooh323", ver:"1:16.28.0~dfsg-0+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-tests", ver:"1:16.28.0~dfsg-0+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail-imapstorage", ver:"1:16.28.0~dfsg-0+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail-odbcstorage", ver:"1:16.28.0~dfsg-0+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-voicemail", ver:"1:16.28.0~dfsg-0+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-vpb", ver:"1:16.28.0~dfsg-0+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk", ver:"1:16.28.0~dfsg-0+deb10u3", rls:"DEB10"))) {
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
