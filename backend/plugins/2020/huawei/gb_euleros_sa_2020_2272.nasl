# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.2272");
  script_version("2020-10-30T10:45:23+0000");
  script_cve_id("CVE-2017-15705", "CVE-2018-11781", "CVE-2019-12420", "CVE-2020-1931");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-11-02 14:55:55 +0000 (Mon, 02 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-10-30 10:45:23 +0000 (Fri, 30 Oct 2020)");
  script_name("Huawei EulerOS: Security Advisory for spamassassin (EulerOS-SA-2020-2272)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP5");

  script_xref(name:"EulerOS-SA", value:"2020-2272");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2272");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'spamassassin' package(s) announced via the EulerOS-SA-2020-2272 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A denial of service vulnerability was identified that exists in Apache SpamAssassin before 3.4.2. The vulnerability arises with certain unclosed tags in emails that cause markup to be handled incorrectly leading to scan timeouts. In Apache SpamAssassin, using HTML::Parser, we setup an object and hook into the begin and end tag event handlers In both cases, the 'open' event is immediately followed by a 'close' event - even if the tag *does not* close in the HTML being parsed. Because of this, we are missing the 'text' event to deal with the object normally. This can cause carefully crafted emails that might take more scan time than expected leading to a Denial of Service. The issue is possibly a bug or design decision in HTML::Parser that specifically impacts the way Apache SpamAssassin uses the module with poorly formed html. The exploit has been seen in the wild but not believed to have been purposefully part of a Denial of Service attempt. We are concerned that there may be attempts to abuse the vulnerability in the future.(CVE-2017-15705)

Apache SpamAssassin 3.4.2 fixes a local user code injection in the meta rule syntax.(CVE-2018-11781)

In Apache SpamAssassin before 3.4.3, a message can be crafted in a way to use excessive resources. Upgrading to SA 3.4.3 as soon as possible is the recommended fix but details will not be shared publicly.(CVE-2019-12420)

A command execution issue was found in Apache SpamAssassin prior to 3.4.3. Carefully crafted nefarious Configuration (.cf) files can be configured to run system commands similar to CVE-2018-11805. This issue is less stealthy and attempts to exploit the issue will throw warnings. Thanks to Damian Lukowski at credativ for reporting the issue ethically. With this bug unpatched, exploits can be injected in a number of scenarios though doing so remotely is difficult. In addition to upgrading to SA 3.4.4, we again recommend that users should only use update channels or 3rd party .cf files from trusted places.(CVE-2020-1931)");

  script_tag(name:"affected", value:"'spamassassin' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"spamassassin", rpm:"spamassassin~3.4.0~2.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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