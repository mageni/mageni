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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6021.1");
  script_cve_id("CVE-2023-1528", "CVE-2023-1529", "CVE-2023-1530", "CVE-2023-1531", "CVE-2023-1532", "CVE-2023-1533", "CVE-2023-1534", "CVE-2023-1810", "CVE-2023-1811", "CVE-2023-1812", "CVE-2023-1813", "CVE-2023-1814", "CVE-2023-1815", "CVE-2023-1816", "CVE-2023-1818", "CVE-2023-1819", "CVE-2023-1820", "CVE-2023-1821", "CVE-2023-1822", "CVE-2023-1823");
  script_tag(name:"creation_date", value:"2023-04-17 04:09:06 +0000 (Mon, 17 Apr 2023)");
  script_version("2023-04-17T10:09:22+0000");
  script_tag(name:"last_modification", value:"2023-04-17 10:09:22 +0000 (Mon, 17 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-27 03:55:00 +0000 (Mon, 27 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-6021-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6021-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6021-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser' package(s) announced via the USN-6021-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Chromium did not properly manage memory in several
components. A remote attacker could possibly use this issue to corrupt
memory via a crafted HTML page, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2023-1528, CVE-2023-1530,
CVE-2023-1531, CVE-2023-1533, CVE-2023-1811, CVE-2023-1815, CVE-2023-1818)

It was discovered that Chromium could be made to access memory out of
bounds in WebHID. A remote attacker could possibly use this issue to
corrupt memory via a malicious HID device, resulting in a denial of
service, or possibly execute arbitrary code. (CVE-2023-1529)

It was discovered that Chromium could be made to access memory out of
bounds in several components. A remote attacker could possibly use this
issue to corrupt memory via a crafted HTML page, resulting in a denial of
service, or possibly execute arbitrary code. (CVE-2023-1532,
CVE-2023-1534, CVE-2023-1810, CVE-2023-1812, CVE-2023-1819, CVE-2023-1820)

It was discovered that Chromium contained an inappropriate implementation
in the Extensions component. A remote attacker who convinced a user to
install a malicious extension could possibly use this issue to bypass file
access restrictions via a crafted HTML page. (CVE-2023-1813)

It was discovered that Chromium did not properly validate untrusted input
in the Safe Browsing component. A remote attacker could possibly use this
issue to bypass download checking via a crafted HTML page. (CVE-2023-1814)

It was discovered that Chromium contained an inappropriate implementation
in the Picture In Picture component. A remote attacker could possibly use
this issue to perform navigation spoofing via a crafted HTML page.
(CVE-2023-1816)

It was discovered that Chromium contained an inappropriate implementation
in the WebShare component. A remote attacker could possibly use this issue
to hide the contents of the Omnibox (URL bar) via a crafted HTML page.
(CVE-2023-1821)

It was discovered that Chromium contained an inappropriate implementation
in the Navigation component. A remote attacker could possibly use this
issue to perform domain spoofing via a crafted HTML page. (CVE-2023-1822)

It was discovered that Chromium contained an inappropriate implementation
in the FedCM component. A remote attacker could possibly use this issue to
bypass navigation restrictions via a crafted HTML page. (CVE-2023-1823)");

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

  if(!isnull(res = isdpkgvuln(pkg:"chromium-browser", ver:"112.0.5615.49-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
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
