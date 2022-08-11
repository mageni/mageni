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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1434");
  script_version("2020-01-23T11:46:15+0000");
  script_cve_id("CVE-2013-1752", "CVE-2013-4238", "CVE-2014-4616", "CVE-2014-7185", "CVE-2014-9365", "CVE-2016-0772", "CVE-2016-2183", "CVE-2016-5636", "CVE-2016-5699", "CVE-2017-1000158", "CVE-2018-1060", "CVE-2018-1061", "CVE-2018-14647", "CVE-2019-5010", "CVE-2019-9636", "CVE-2019-9948");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 11:46:15 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:46:15 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for python (EulerOS-SA-2019-1434)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1434");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'python' package(s) announced via the EulerOS-SA-2019-1434 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that Python's smtplib library did not return an exception when StartTLS failed to be established in the SMTP.starttls() function. A man in the middle attacker could strip out the STARTTLS command without generating an exception on the Python SMTP client application, preventing the establishment of the TLS layer.(CVE-2016-0772)

A vulnerability was discovered in Python, in the built-in zipimporter. A specially crafted zip file placed in a module path such that it would be loaded by a later 'import' statement could cause a heap overflow, leading to arbitrary code execution.(CVE-2016-5636)

A flaw was found in the way the DES/3DES cipher was used as part of the TLS/SSL protocol. A man-in-the-middle attacker could use this flaw to recover some plaintext data by capturing large amounts of encrypted traffic between TLS/SSL server and client if the communication used a DES/3DES based ciphersuite.(CVE-2016-2183)

The Python standard library HTTP client modules (such as httplib or urllib) did not perform verification of TLS/SSL certificates when connecting to HTTPS servers. A man-in-the-middle attacker could use this flaw to hijack connections and eavesdrop or modify transferred data.(CVE-2014-9365)

An integer overflow flaw was found in the way the buffer() function handled its offset and size arguments. An attacker able to control those arguments could use this flaw to disclose portions of the application memory or cause it to crash.(CVE-2014-7185)

A flaw was found in the way catastrophic backtracking was implemented in python's pop3lib's apop() method. An attacker could use this flaw to cause denial of service.(CVE-2018-1060)

The ssl.match_hostname function in the SSL module in Python 2.6 through 3.4 does not properly handle a '\\0' character in a domain name in the Subject Alternative Name field of an X.509 certificate, which allows man-in-the-middle attackers to spoof arbitrary SSL servers via a crafted certificate issued by a legitimate Certification Authority, a related issue to CVE-2009-2408.(CVE-2013-4238)

It was found that the Python's httplib library (used by urllib, urllib2 and others) did not properly check HTTPConnection.putheader() function arguments. An attacker could use this flaw to inject additional headers in a Python application that allowed user provided header names or values.(CVE-2016-5699)

CPython (aka Python) up to 2.7.13 is vulnerable to an integer overflow in the PyString_DecodeEscape function in stringobject.c, resulting in heap-based buffer overflow (and possible arbitrary code execution)(CVE-2017-1000158)

A flaw was found in the way cat ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'python' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"python", rpm:"python~2.7.5~69.h19", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.7.5~69.h19", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libs", rpm:"python-libs~2.7.5~69.h19", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tools", rpm:"python-tools~2.7.5~69.h19", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.7.5~69.h19", rls:"EULEROSVIRT-3.0.1.0"))) {
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