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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1284");
  script_cve_id("CVE-2021-3733", "CVE-2021-3737", "CVE-2021-4189", "CVE-2022-0391");
  script_tag(name:"creation_date", value:"2023-01-31 04:21:24 +0000 (Tue, 31 Jan 2023)");
  script_version("2023-01-31T10:08:41+0000");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-15 17:01:00 +0000 (Tue, 15 Mar 2022)");

  script_name("Huawei EulerOS: Security Advisory for python (EulerOS-SA-2023-1284)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.2\.2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1284");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1284");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'python' package(s) announced via the EulerOS-SA-2023-1284 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in Python, specifically within the urllib.parse module. This module helps break Uniform Resource Locator (URL) strings into components. The issue involves how the urlparse method does not sanitize input and allows characters like '\r' and '\n' in the URL path. This flaw allows an attacker to input a crafted URL, leading to injection attacks. This flaw affects Python versions prior to 3.10.0b1, 3.9.5, 3.8.11, 3.7.11 and 3.6.14.(CVE-2022-0391)

There's a flaw in urllib's AbstractBasicAuthHandler class. An attacker who controls a malicious HTTP server that an HTTP client (such as web browser) connects to, could trigger a Regular Expression Denial of Service (ReDOS) during an authentication request with a specially crafted payload that is sent by the server to the client. The greatest threat that this flaw poses is to application availability.(CVE-2021-3733)

A flaw was found in python. An improperly handled HTTP response in the HTTP client code of python may allow a remote attacker, who controls the HTTP server, to make the client script enter an infinite loop, consuming CPU time. The highest threat from this vulnerability is to system availability.(CVE-2021-3737)

Python 2 is an old version of the language that is incompatible with the 3.xline of releases. The language is mostly the same, but many details, especiallyhow built-in objects like dictionaries and strings work, have changedconsiderably, and a lot of deprecated features have finally been removed in(CVE-2021-4189)");

  script_tag(name:"affected", value:"'python' package(s) on Huawei EulerOS Virtualization 3.0.2.2.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROSVIRT-3.0.2.2") {

  if(!isnull(res = isrpmvuln(pkg:"python", rpm:"python~2.7.5~69.h27", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libs", rpm:"python-libs~2.7.5~69.h27", rls:"EULEROSVIRT-3.0.2.2"))) {
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
