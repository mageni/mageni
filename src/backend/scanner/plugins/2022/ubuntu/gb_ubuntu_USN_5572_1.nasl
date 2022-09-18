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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5572.1");
  script_cve_id("CVE-2022-26365", "CVE-2022-33740", "CVE-2022-33741");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-15 17:17:00 +0000 (Fri, 15 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-5572-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5572-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5572-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws' package(s) announced via the USN-5572-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Roger Pau Monne discovered that the Xen virtual block driver in the Linux
kernel did not properly initialize memory pages to be used for shared
communication with the backend. A local attacker could use this to expose
sensitive information (guest kernel memory). (CVE-2022-26365)

Roger Pau Monne discovered that the Xen paravirtualization frontend in the
Linux kernel did not properly initialize memory pages to be used for shared
communication with the backend. A local attacker could use this to expose
sensitive information (guest kernel memory). (CVE-2022-33740)

It was discovered that the Xen paravirtualization frontend in the Linux
kernel incorrectly shared unrelated data when communicating with certain
backends. A local attacker could use this to cause a denial of service
(guest crash) or expose sensitive information (guest kernel memory).
(CVE-2022-33741)");

  script_tag(name:"affected", value:"'linux-aws' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1148-aws", ver:"4.4.0-1148.163", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1148.152", rls:"UBUNTU16.04 LTS"))) {
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
