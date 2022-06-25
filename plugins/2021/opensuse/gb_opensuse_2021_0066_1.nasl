# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853753");
  script_version("2021-04-21T07:29:02+0000");
  script_cve_id("CVE-2020-8265", "CVE-2020-8277", "CVE-2020-8287");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 05:02:50 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for nodejs14 (openSUSE-SU-2021:0066-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0066-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WYFKSVZAWD7RDU5OST2FANHMDWL4VNM7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs14'
  package(s) announced via the openSUSE-SU-2021:0066-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs14 fixes the following issues:

  - New upstream LTS version 14.15.4:

  * CVE-2020-8265: use-after-free in TLSWrap (High) bug in TLS
         implementation. When writing to a TLS enabled socket,
         node::StreamBase::Write calls node::TLSWrap::DoWrite with a freshly
         allocated WriteWrap object as first argument. If the DoWrite method
         does not return an error, this object is passed back to the caller as
         part of a StreamWriteResult structure. This may be exploited to
         corrupt memory leading to a Denial of Service or potentially other
         exploits (bsc#1180553)

  * CVE-2020-8287: HTTP Request Smuggling allow two copies of a header
         field in a http request. For example, two Transfer-Encoding header
         fields. In this case Node.js identifies the first header field and
         ignores the second. This can lead to HTTP Request Smuggling

  - New upstream LTS version 14.15.3:

  * deps:
         + upgrade npm to 6.14.9
         + update acorn to v8.0.4

  * http2: check write not scheduled in scope destructor

  * stream: fix regression on duplex end

  - New upstream LTS version 14.15.1:

  * deps: Denial of Service through DNS request (High). A Node.js
         application that allows an attacker to trigger a DNS request for a
         host of their choice could trigger a Denial of Service by getting the
         application to resolve a DNS record with a larger number of responses
         (bsc#1178882, CVE-2020-8277)

     This update was imported from the SUSE:SLE-15-SP2:Update update project.");

  script_tag(name:"affected", value:"'nodejs14' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-docs", rpm:"nodejs14-docs~14.15.4~lp152.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14", rpm:"nodejs14~14.15.4~lp152.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-debuginfo", rpm:"nodejs14-debuginfo~14.15.4~lp152.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-debugsource", rpm:"nodejs14-debugsource~14.15.4~lp152.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-devel", rpm:"nodejs14-devel~14.15.4~lp152.5.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm14", rpm:"npm14~14.15.4~lp152.5.1", rls:"openSUSELeap15.2"))) {
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
