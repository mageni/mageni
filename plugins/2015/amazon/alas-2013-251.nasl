# Copyright (C) 2015 Eero Volotinen
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
  script_oid("1.3.6.1.4.1.25623.1.0.120544");
  script_version("2021-07-05T02:00:48+0000");
  script_tag(name:"creation_date", value:"2015-09-08 13:29:07 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"last_modification", value:"2021-12-07 11:00:26 +0000 (Tue, 07 Dec 2021)");
  script_name("Amazon Linux: Security Advisory (ALAS-2013-251)");
  script_tag(name:"insight", value:"Two flaws were found in Wireshark. If Wireshark read a malformed packet off a network or opened a malicious dump file, it could crash or, possibly, execute arbitrary code as the user running Wireshark. (CVE-2013-3559, CVE-2013-4083 )Several denial of service flaws were found in Wireshark. Wireshark could crash or stop responding if it read a malformed packet off a network, or opened a malicious dump file. (CVE-2012-2392, CVE-2012-3825, CVE-2012-4285, CVE-2012-4288, CVE-2012-4289, CVE-2012-4290, CVE-2012-4291, CVE-2012-4292, CVE-2012-5595, CVE-2012-5597, CVE-2012-5598, CVE-2012-5599, CVE-2012-5600, CVE-2012-6056, CVE-2012-6059, CVE-2012-6060, CVE-2012-6061, CVE-2012-6062, CVE-2013-3557, CVE-2013-3561, CVE-2013-4081, CVE-2013-4927, CVE-2013-4931, CVE-2013-4932, CVE-2013-4933, CVE-2013-4934, CVE-2013-4935, CVE-2013-4936, CVE-2013-5721 )");
  script_tag(name:"solution", value:"Run yum update wireshark to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2013-251.html");
  script_cve_id("CVE-2013-4931", "CVE-2012-5598", "CVE-2012-3825", "CVE-2012-2392", "CVE-2012-6056", "CVE-2013-4081", "CVE-2013-4083", "CVE-2012-6061", "CVE-2012-6060", "CVE-2012-6059", "CVE-2013-4932", "CVE-2012-4288", "CVE-2012-4289", "CVE-2012-4285", "CVE-2013-3561", "CVE-2012-4291", "CVE-2013-4933", "CVE-2013-4934", "CVE-2012-6062", "CVE-2012-4292", "CVE-2013-5721", "CVE-2012-4290", "CVE-2012-5599", "CVE-2013-3559", "CVE-2012-5597", "CVE-2013-3557", "CVE-2012-5595", "CVE-2012-5600", "CVE-2013-4935", "CVE-2013-4927", "CVE-2013-4936");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"The remote host is missing an update announced via the referenced Security Advisory.");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
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
  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.8.10~4.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~1.8.10~4.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~1.8.10~4.12.amzn1", rls:"AMAZON"))) {
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
