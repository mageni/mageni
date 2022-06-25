# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.120713");
  script_version("2021-10-14T11:01:30+0000");
  script_tag(name:"creation_date", value:"2016-10-26 15:38:16 +0300 (Wed, 26 Oct 2016)");
  script_tag(name:"last_modification", value:"2021-12-06 11:03:13 +0000 (Mon, 06 Dec 2021)");
  script_name("Amazon Linux: Security Advisory (ALAS-2016-724)");
  script_tag(name:"insight", value:"It was found that Python's httplib library (used urllib, urllib2 and others) did not properly
  check HTTP header input in HTTPConnection.putheader(). An attacker could use this flow to inject additional headers in a Python
  application that allows user provided header name or values. (CVE-2016-5699 )It was found that Python's smtplib library did not
  return an exception if StartTLS fails to establish correctly in the SMTP.starttls() function. An attacker with ability to launch
  an active man in the middle attack could strip out the STARTTLS command without generating an exception on the python SMTP client
  application, preventing the establishment of the TLS layer. (CVE-2016-0772 )A vulnerability was discovered in Python, in the built-in zipimporter.
  A specially crafted zip file placed in a module path such that it would be loaded by a later 'import' statement could cause a heap overflow,
  leading to arbitrary code execution. (CVE-2016-5636 )");
  script_tag(name:"solution", value:"Run yum update python26 to update your system.

  Run yum update python27 to update your system.

  Run yum update python34 to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-724.html");
  script_cve_id("CVE-2016-5699", "CVE-2016-5636", "CVE-2016-0772");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-09 11:29:00 +0000 (Sat, 09 Feb 2019)");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"The remote host is missing an update announced via the referenced Security Advisory.");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "AMAZON") {
  if(!isnull(res = isrpmvuln(pkg:"libs", rpm:"libs~2.6.9~2.86.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tools", rpm:"tools~2.6.9~2.86.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"test", rpm:"test~2.6.9~2.86.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"debuginfo", rpm:"debuginfo~2.6.9~2.86.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"devel", rpm:"devel~2.6.9~2.86.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"devel", rpm:"devel~2.7.10~4.122.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"test", rpm:"test~2.7.10~4.122.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tools", rpm:"tools~2.7.10~4.122.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"debuginfo", rpm:"debuginfo~2.7.10~4.122.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libs", rpm:"libs~2.7.10~4.122.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tools", rpm:"tools~3.4.3~1.32.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"test", rpm:"test~3.4.3~1.32.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"devel", rpm:"devel~3.4.3~1.32.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"debuginfo", rpm:"debuginfo~3.4.3~1.32.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libs", rpm:"libs~3.4.3~1.32.amzn1", rls:"AMAZON"))) {
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
