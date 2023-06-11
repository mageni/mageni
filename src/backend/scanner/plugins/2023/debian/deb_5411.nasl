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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5411");
  script_cve_id("CVE-2020-35980", "CVE-2021-21852", "CVE-2021-33361", "CVE-2021-33363", "CVE-2021-33364", "CVE-2021-33365", "CVE-2021-33366", "CVE-2021-36412", "CVE-2021-36414", "CVE-2021-36417", "CVE-2021-4043", "CVE-2021-40559", "CVE-2021-40562", "CVE-2021-40563", "CVE-2021-40564", "CVE-2021-40565", "CVE-2021-40566", "CVE-2021-40567", "CVE-2021-40568", "CVE-2021-40569", "CVE-2021-40570", "CVE-2021-40571", "CVE-2021-40572", "CVE-2021-40574", "CVE-2021-40575", "CVE-2021-40576", "CVE-2021-40592", "CVE-2021-40606", "CVE-2021-40608", "CVE-2021-40609", "CVE-2021-40944", "CVE-2021-41456", "CVE-2021-41457", "CVE-2021-41459", "CVE-2021-45262", "CVE-2021-45263", "CVE-2021-45267", "CVE-2021-45291", "CVE-2021-45292", "CVE-2021-45297", "CVE-2021-45760", "CVE-2021-45762", "CVE-2021-45763", "CVE-2021-45764", "CVE-2021-45767", "CVE-2021-45831", "CVE-2021-46038", "CVE-2021-46039", "CVE-2021-46040", "CVE-2021-46041", "CVE-2021-46042", "CVE-2021-46043", "CVE-2021-46044", "CVE-2021-46045", "CVE-2021-46046", "CVE-2021-46047", "CVE-2021-46049", "CVE-2021-46051", "CVE-2022-1035", "CVE-2022-1222", "CVE-2022-1441", "CVE-2022-1795", "CVE-2022-2454", "CVE-2022-24574", "CVE-2022-24577", "CVE-2022-24578", "CVE-2022-26967", "CVE-2022-27145", "CVE-2022-27147", "CVE-2022-29537", "CVE-2022-3222", "CVE-2022-36190", "CVE-2022-36191", "CVE-2022-38530", "CVE-2022-3957", "CVE-2022-4202", "CVE-2022-43255", "CVE-2022-45202", "CVE-2022-45283", "CVE-2022-45343", "CVE-2022-47086", "CVE-2022-47091", "CVE-2022-47094", "CVE-2022-47095", "CVE-2022-47657", "CVE-2022-47659", "CVE-2022-47660", "CVE-2022-47661", "CVE-2022-47662", "CVE-2022-47663", "CVE-2023-0770", "CVE-2023-0818", "CVE-2023-0819", "CVE-2023-0866", "CVE-2023-1448", "CVE-2023-1449", "CVE-2023-1452", "CVE-2023-1654", "CVE-2023-23143", "CVE-2023-23144", "CVE-2023-23145", "CVE-2023-2837", "CVE-2023-2838", "CVE-2023-2839", "CVE-2023-2840");
  script_tag(name:"creation_date", value:"2023-05-29 04:22:35 +0000 (Mon, 29 May 2023)");
  script_version("2023-05-30T09:08:51+0000");
  script_tag(name:"last_modification", value:"2023-05-30 09:08:51 +0000 (Tue, 30 May 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-26 02:13:00 +0000 (Fri, 26 May 2023)");

  script_name("Debian: Security Advisory (DSA-5411)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5411");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5411");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5411");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/gpac");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gpac' package(s) announced via the DSA-5411 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues were found in GPAC multimedia framework, which could result in denial of service or potentially the execution of arbitrary code.

For the stable distribution (bullseye), these problems have been fixed in version 1.0.1+dfsg1-4+deb11u2.

We recommend that you upgrade your gpac packages.

For the detailed security status of gpac please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'gpac' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"gpac-modules-base", ver:"1.0.1+dfsg1-4+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gpac", ver:"1.0.1+dfsg1-4+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgpac-dev", ver:"1.0.1+dfsg1-4+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgpac10", ver:"1.0.1+dfsg1-4+deb11u2", rls:"DEB11"))) {
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
