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
  script_oid("1.3.6.1.4.1.25623.1.0.853573");
  script_version("2020-11-11T08:18:25+0000");
  script_cve_id("CVE-2014-3577", "CVE-2015-5262");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-11-11 11:10:35 +0000 (Wed, 11 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-09 04:01:06 +0000 (Mon, 09 Nov 2020)");
  script_name("openSUSE: Security Advisory for apache-commons-httpclient (openSUSE-SU-2020:1875-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:1875-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-11/msg00033.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache-commons-httpclient'
  package(s) announced via the openSUSE-SU-2020:1875-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache-commons-httpclient fixes the following issues:

  - http/conn/ssl/SSLConnectionSocketFactory.java ignores the
  http.socket.timeout configuration setting during an SSL handshake, which
  allows remote attackers to cause a denial of service (HTTPS call hang)
  via unspecified vectors. [bsc#945190, CVE-2015-5262]

  - org.apache.http.conn.ssl.AbstractVerifier does not properly verify that
  the server hostname matches a domain name in the subject's Common Name
  (CN) or subjectAltName field of the X.509 certificate, which allows MITM
  attackers to spoof SSL servers via a 'CN=' string in a field in the
  distinguished name (DN)
  of a certificate. [bsc#1178171, CVE-2014-3577]

  This update was imported from the SUSE:SLE-15-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1875=1");

  script_tag(name:"affected", value:"'apache-commons-httpclient' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-httpclient", rpm:"apache-commons-httpclient~3.1~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-httpclient-demo", rpm:"apache-commons-httpclient-demo~3.1~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-httpclient-javadoc", rpm:"apache-commons-httpclient-javadoc~3.1~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-httpclient-manual", rpm:"apache-commons-httpclient-manual~3.1~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
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