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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2019.3707.2");
  script_cve_id("CVE-2016-7426", "CVE-2016-7427", "CVE-2016-7428", "CVE-2016-9310", "CVE-2016-9311", "CVE-2017-6462", "CVE-2017-6463", "CVE-2018-7183", "CVE-2018-7185");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-3707-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3707-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3707-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the USN-3707-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3707-1 and USN-3349-1 fixed several vulnerabilities in NTP. This update
provides the corresponding update for Ubuntu 12.04 ESM.

Original advisory details:

 Miroslav Lichvar discovered that NTP incorrectly handled certain spoofed
 addresses when performing rate limiting. A remote attacker could possibly
 use this issue to perform a denial of service. (CVE-2016-7426)

 Matthew Van Gundy discovered that NTP incorrectly handled certain crafted
 broadcast mode packets. A remote attacker could possibly use this issue to
 perform a denial of service. (CVE-2016-7427, CVE-2016-7428)

 Matthew Van Gundy discovered that NTP incorrectly handled certain control
 mode packets. A remote attacker could use this issue to set or unset traps.
 (CVE-2016-9310)

 Matthew Van Gundy discovered that NTP incorrectly handled the trap service.
 A remote attacker could possibly use this issue to cause NTP to crash, resulting
 in a denial of service. (CVE-2016-9311)

 It was discovered that the NTP legacy DPTS refclock driver incorrectly handled
 the /dev/datum device. A local attacker could possibly use this issue to cause
 a denial of service. (CVE-2017-6462)

 It was discovered that NTP incorrectly handled certain invalid settings in a
 :config directive. A remote authenticated user could possibly use this issue
 to cause NTP to crash, resulting in a denial of service. (CVE-2017-6463)

 Michael Macnair discovered that NTP incorrectly handled certain responses.
 A remote attacker could possibly use this issue to execute arbitrary code.
 (CVE-2018-7183)

 Miroslav Lichvar discovered that NTP incorrectly handled certain
 zero-origin timestamps. A remote attacker could possibly use this issue to
 cause a denial of service. (CVE-2018-7185)");

  script_tag(name:"affected", value:"'ntp' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.6.p3+dfsg-1ubuntu3.12", rls:"UBUNTU12.04 LTS"))) {
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
