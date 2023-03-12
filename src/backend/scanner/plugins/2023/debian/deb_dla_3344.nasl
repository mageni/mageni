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
  script_oid("1.3.6.1.4.1.25623.1.0.893344");
  script_cve_id("CVE-2022-43548", "CVE-2023-23920");
  script_tag(name:"creation_date", value:"2023-02-26 02:00:07 +0000 (Sun, 26 Feb 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-08 16:02:00 +0000 (Thu, 08 Dec 2022)");

  script_name("Debian: Security Advisory (DLA-3344)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3344");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3344");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/nodejs");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nodejs' package(s) announced via the DLA-3344 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vulnerabilities have been found in Node.js, which could result in DNS rebinding or arbitrary code execution.

CVE-2022-43548

The Node.js rebinding protector for --inspect still allows invalid IP addresses, specifically in octal format, which browsers such as Firefox attempt to resolve via DNS. When combined with an active --inspect session, such as when using VSCode, an attacker can perform DNS rebinding and execute arbitrary code.

CVE-2023-23920

Ben Noordhuis reported that Node.js would search and potentially load ICU data when running with elevated privileges. Node.js now builds with ICU_NO_USER_DATA_OVERRIDE to avoid this.

For Debian 10 buster, these problems have been fixed in version 10.24.0~dfsg-1~deb10u3.

We recommend that you upgrade your nodejs packages.

For the detailed security status of nodejs please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'nodejs' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libnode-dev", ver:"10.24.0~dfsg-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnode64", ver:"10.24.0~dfsg-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-doc", ver:"10.24.0~dfsg-1~deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"10.24.0~dfsg-1~deb10u3", rls:"DEB10"))) {
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
