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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5348.3");
  script_cve_id("CVE-2018-13982", "CVE-2018-16831", "CVE-2021-21408", "CVE-2021-26119", "CVE-2021-26120", "CVE-2021-29454");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-26 10:15:00 +0000 (Wed, 26 May 2021)");

  script_name("Ubuntu: Security Advisory (USN-5348-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5348-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5348-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'smarty3' package(s) announced via the USN-5348-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5348-1 fixed several vulnerabilities in Smarty. This update provides
the fixes for CVE-2021-21408, CVE-2021-26119, CVE-2021-26120 and
CVE-2021-29454 for Ubuntu 20.04 ESM.

Original advisory details:

 David Gnedt and Thomas Konrad discovered that Smarty was incorrectly
 sanitizing the paths present in the templates. An attacker could possibly
 use this use to read arbitrary files when controlling the executed
 template. (CVE-2018-13982)

 It was discovered that Smarty was incorrectly sanitizing the paths
 present in the templates. An attacker could possibly use this use to read
 arbitrary files when controlling the executed template. (CVE-2018-16831)

 It was discovered that Smarty was incorrectly validating security policy
 data, allowing the execution of static classes even when not permitted by
 the security settings. An attacker could possibly use this issue to
 execute arbitrary code. (CVE-2021-21408)

 It was discovered that Smarty was incorrectly managing access control to
 template objects, which allowed users to perform a sandbox escape. An
 attacker could possibly use this issue to send specially crafted input to
 applications that use Smarty and execute arbitrary code. (CVE-2021-26119)

 It was discovered that Smarty was not checking for special characters
 when setting function names during plugin compile operations. An attacker
 could possibly use this issue to send specially crafted input to
 applications that use Smarty and execute arbitrary code. (CVE-2021-26120)

 It was discovered that Smarty was incorrectly sanitizing characters in
 math strings processed by the math function. An attacker could possibly
 use this issue to send specially crafted input to applications that use
 Smarty and execute arbitrary code. (CVE-2021-29454)");

  script_tag(name:"affected", value:"'smarty3' package(s) on Ubuntu 20.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"smarty3", ver:"3.1.34+20190228.1.c9f0de05+selfpack1-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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
