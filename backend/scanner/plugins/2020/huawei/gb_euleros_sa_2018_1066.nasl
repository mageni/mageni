# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2018.1066");
  script_version("2020-01-23T11:11:17+0000");
  script_cve_id("CVE-2017-0898", "CVE-2017-0899", "CVE-2017-0900", "CVE-2017-0901", "CVE-2017-0902", "CVE-2017-0903", "CVE-2017-10784", "CVE-2017-14033", "CVE-2017-14064", "CVE-2017-17405", "CVE-2017-17790");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 11:11:17 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:11:17 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for ruby (EulerOS-SA-2018-1066)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP1");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1066");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'ruby' package(s) announced via the EulerOS-SA-2018-1066 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Net::FTP module did not properly process filenames in combination with certain operations. A remote attacker could exploit this flaw to execute arbitrary commands by setting up a malicious FTP server and tricking a user or Ruby application into downloading files with specially crafted names using the Net::FTP module. (CVE-2017-17405)

A buffer underflow was found in ruby's sprintf function. An attacker, with ability to control its format string parameter, could send a specially crafted string that would disclose heap memory or crash the interpreter. (CVE-2017-0898)

It was found that rubygems did not sanitize gem names during installation of a given gem. A specially crafted gem could use this flaw to install files outside of the regular directory. (CVE-2017-0901)

A vulnerability was found where rubygems did not sanitize DNS responses when requesting the hostname of the rubygems server for a domain, via a _rubygems._tcp DNS SRV query. An attacker with the ability to manipulate DNS responses could direct the gem command towards a different domain. (CVE-2017-0902)

A vulnerability was found where the rubygems module was vulnerable to an unsafe YAML deserialization when inspecting a gem. Applications inspecting gem files without installing them can be tricked to execute arbitrary code in the context of the ruby interpreter. (CVE-2017-0903)

It was found that WEBrick did not sanitize all its log messages. If logs were printed in a terminal, an attacker could interact with the terminal via the use of escape sequences. (CVE-2017-10784)

It was found that the decode method of the OpenSSL::ASN1 module was vulnerable to buffer underrun. An attacker could pass a specially crafted string to the application in order to crash the ruby interpreter, causing a denial of service. (CVE-2017-14033)

A vulnerability was found where rubygems did not properly sanitize gems' specification text. A specially crafted gem could interact with the terminal via the use of escape sequences. (CVE-2017-0899)

It was found that rubygems could use an excessive amount of CPU while parsing a sufficiently long gem summary. A specially crafted gem from a gem repository could freeze gem commands attempting to parse its summary. (CVE-2017-0900)

A buffer overflow vulnerability was found in the JSON extension of ruby. An attacker with the ability to pass a specially crafted JSON input to the extension could use this flaw to expose the interpreter's heap memory. (CVE-2017-14064)");

  script_tag(name:"affected", value:"'ruby' package(s) on Huawei EulerOS V2.0SP1.");

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

if(release == "EULEROS-2.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~2.0.0.648~33.h2", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~2.0.0.648~33.h2", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~2.0.0.648~33.h2", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);