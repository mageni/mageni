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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5881.1");
  script_cve_id("CVE-2023-0471", "CVE-2023-0472", "CVE-2023-0473", "CVE-2023-0474", "CVE-2023-0696", "CVE-2023-0698", "CVE-2023-0699", "CVE-2023-0700", "CVE-2023-0701", "CVE-2023-0702", "CVE-2023-0703", "CVE-2023-0704", "CVE-2023-0705");
  script_tag(name:"creation_date", value:"2023-02-22 04:10:55 +0000 (Wed, 22 Feb 2023)");
  script_version("2023-02-22T10:09:59+0000");
  script_tag(name:"last_modification", value:"2023-02-22 10:09:59 +0000 (Wed, 22 Feb 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-16 15:16:00 +0000 (Thu, 16 Feb 2023)");

  script_name("Ubuntu: Security Advisory (USN-5881-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5881-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5881-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser' package(s) announced via the USN-5881-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Chromium did not properly manage memory. A remote
attacker could possibly use these issues to cause a denial of service or
execute arbitrary code via a crafted HTML page. (CVE-2023-0471,
CVE-2023-0472, CVE-2023-0473, CVE-2023-0696, CVE-2023-0698, CVE-2023-0699,
CVE-2023-0702, CVE-2023-0705)

It was discovered that Chromium did not properly manage memory. A remote
attacker who convinced a user to install a malicious extension could
possibly use this issue to corrupt memory via a Chrome web app.
(CVE-2023-0474)

It was discovered that Chromium contained an inappropriate implementation
in the Download component. A remote attacker could possibly use this issue
to spoof contents of the Omnibox (URL bar) via a crafted HTML page.
(CVE-2023-0700)

It was discovered that Chromium did not properly manage memory. A remote
attacker who convinced a user to engage in specific UI interactions could
possibly use these issues to cause a denial of service or execute
arbitrary code. (CVE-2023-0701, CVE-2023-0703)

It was discovered that Chromium insufficiently enforced policies. A remote
attacker could possibly use this issue to bypass same origin policy and
proxy settings via a crafted HTML page. (CVE-2023-0704)");

  script_tag(name:"affected", value:"'chromium-browser' package(s) on Ubuntu 18.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser", ver:"110.0.5481.100-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
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
