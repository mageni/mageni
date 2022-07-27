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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2321");
  script_version("2020-01-23T15:42:05+0000");
  script_cve_id("CVE-2018-5738", "CVE-2018-5745", "CVE-2019-6465");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-01-23 15:42:05 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:47:03 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for bind (EulerOS-SA-2019-2321)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.3\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2321");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'bind' package(s) announced via the EulerOS-SA-2019-2321 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Change #4777 (introduced in October 2017) introduced an unforeseen issue in releases which were issued after that date, affecting which clients are permitted to make recursive queries to a BIND nameserver. The intended (and documented) behavior is that if an operator has not specified a value for the 'allow-recursion' setting, it SHOULD default to one of the following: none, if 'recursion no, ' is set in named.conf, a value inherited from the 'allow-query-cache' or 'allow-query' settings IF 'recursion yes, ' (the default for that setting) AND match lists are explicitly set for 'allow-query-cache' or 'allow-query' (see the BIND9 Administrative Reference Manual section 6.2 for more details), or the intended default of 'allow-recursion {localhost, localnets, }, ' if 'recursion yes, ' is in effect and no values are explicitly set for 'allow-query-cache' or 'allow-query'. However, because of the regression introduced by change #4777, it is possible when 'recursion yes, ' is in effect and no match list values are provided for 'allow-query-cache' or 'allow-query' for the setting of 'allow-recursion' to inherit a setting of all hosts from the 'allow-query' setting default, improperly permitting recursion to all clients. Affects BIND 9.9.12, 9.10.7, 9.11.3, 9.12.0-9.12.1-P2, the development release 9.13.0, and also releases 9.9.12-S1, 9.10.7-S1, 9.11.3-S1, and 9.11.3-S2 from BIND 9 Supported Preview Edition.(CVE-2018-5738)

Controls for zone transfers may not be properly applied to Dynamically Loadable Zones (DLZs) if the zones are writable Versions affected: BIND 9.9.0 - 9.10.8-P1, 9.11.0 - 9.11.5-P2, 9.12.0 - 9.12.3-P2, and versions 9.9.3-S1 - 9.11.5-S3 of BIND 9 Supported Preview Edition. Versions 9.13.0 - 9.13.6 of the 9.13 development branch are also affected. Versions prior to BIND 9.9.0 have not been evaluated for vulnerability to CVE-2019-6465.(CVE-2019-6465)

'managed-keys' is a feature which allows a BIND resolver to automatically maintain the keys used by trust anchors which operators configure for use in DNSSEC validation. Due to an error in the managed-keys feature it is possible for a BIND server which uses managed-keys to exit due to an assertion failure if, during key rollover, a trust anchor's keys are replaced with keys which use an unsupported algorithm. Versions affected: BIND 9.9.0 - 9.10.8-P1, 9.11.0 - 9.11.5-P1, 9.12.0 - 9.12.3-P1, and versions 9.9.3-S1 - 9.11.5-S3 of BIND 9 Supported Preview Edition. Versions 9.13.0 - 9.13.6 of the 9.13 development branch are also affected. Versions prior to BIND 9.9.0 have not been evaluated for vulnerability to CVE-2018-5745.(CVE-2018-5745)");

  script_tag(name:"affected", value:"'bind' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.3.0.");

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

if(release == "EULEROSVIRTARM64-3.0.3.0") {

  if(!isnull(res = isrpmvuln(pkg:"bind-export-libs", rpm:"bind-export-libs~9.11.4~10.P2.h12.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.11.4~10.P2.h12.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs-lite", rpm:"bind-libs-lite~9.11.4~10.P2.h12.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-license", rpm:"bind-license~9.11.4~10.P2.h12.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.11.4~10.P2.h12.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-bind", rpm:"python3-bind~9.11.4~10.P2.h12.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.3.0"))) {
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