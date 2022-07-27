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
  script_oid("1.3.6.1.4.1.25623.1.0.120728");
  script_version("2021-10-07T12:01:23+0000");
  script_tag(name:"creation_date", value:"2016-10-26 15:38:22 +0300 (Wed, 26 Oct 2016)");
  script_tag(name:"last_modification", value:"2021-12-06 11:03:13 +0000 (Mon, 06 Dec 2021)");
  script_name("Amazon Linux: Security Advisory (ALAS-2016-739)");
  script_tag(name:"insight", value:"A heap-based buffer overflow in the parse_packet function in network.c in collectd allows remote attackers to cause a denial of service (daemon crash) or possibly execute arbitrary code via a crafted network packet.");
  script_tag(name:"solution", value:"Run yum update collectd to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-739.html");
  script_cve_id("CVE-2016-6254");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-04 17:42:00 +0000 (Mon, 04 Mar 2019)");
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
  if(!isnull(res = isrpmvuln(pkg:"collectd-gmond", rpm:"collectd-gmond~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-java", rpm:"collectd-java~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-lvm", rpm:"collectd-lvm~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-bind", rpm:"collectd-bind~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-ipvs", rpm:"collectd-ipvs~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-rrdcached", rpm:"collectd-rrdcached~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-generic-jmx", rpm:"collectd-generic-jmx~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-amqp", rpm:"collectd-amqp~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-memcachec", rpm:"collectd-memcachec~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-postgresql", rpm:"collectd-postgresql~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-web", rpm:"collectd-web~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-dbi", rpm:"collectd-dbi~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-email", rpm:"collectd-email~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-mysql", rpm:"collectd-mysql~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-rrdtool", rpm:"collectd-rrdtool~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-curl_xml", rpm:"collectd-curl_xml~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-nginx", rpm:"collectd-nginx~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-snmp", rpm:"collectd-snmp~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Collectd", rpm:"perl-Collectd~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-curl", rpm:"collectd-curl~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-notify_email", rpm:"collectd-notify_email~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-debuginfo", rpm:"collectd-debuginfo~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-ipmi", rpm:"collectd-ipmi~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd", rpm:"collectd~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-iptables", rpm:"collectd-iptables~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-dns", rpm:"collectd-dns~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-varnish", rpm:"collectd-varnish~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-apache", rpm:"collectd-apache~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"collectd-netlink", rpm:"collectd-netlink~5.4.1~1.11.amzn1", rls:"AMAZON"))) {
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
