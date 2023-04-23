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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.1792.1");
  script_cve_id("CVE-2023-24534", "CVE-2023-24536", "CVE-2023-24537", "CVE-2023-24538");
  script_tag(name:"creation_date", value:"2023-04-07 04:17:32 +0000 (Fri, 07 Apr 2023)");
  script_version("2023-04-19T10:08:55+0000");
  script_tag(name:"last_modification", value:"2023-04-19 10:08:55 +0000 (Wed, 19 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-17 16:54:00 +0000 (Mon, 17 Apr 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:1792-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:1792-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20231792-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.19' package(s) announced via the SUSE-SU-2023:1792-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.19 fixes the following issues:
Update to 1.19.8

CVE-2023-24534: security: net/http, net/textproto: denial of service from excessive memory allocation (bsc#1210127)
CVE-2023-24536: security: net/http, net/textproto, mime/multipart: denial of service from excessive resource consumption (bsc#1210128)
CVE-2023-24537: security: go/parser: infinite loop in parsing (bsc#1210129)
CVE-2023-24538: security: html/template: backticks not treated as string delimiters (bsc#1210130)
cmd/go: timeout on darwin-amd64-race builder runtime/pprof: TestLabelSystemstack due to sample with no location internal/testpty: fails on some Linux machines due to incorrect error handling cmd/link: linker fails on linux/amd64 when gcc's lto options are used cmd/link/internal/arm: off-by-one error in trampoline phase call reachability calculation time: time zone lookup using extend string makes wrong start time for non-DST zones runtime: crash on linux-ppc64le");

  script_tag(name:"affected", value:"'go1.19' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Real Time 15-SP3, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"go1.19", rpm:"go1.19~1.19.8~150000.1.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.19-doc", rpm:"go1.19-doc~1.19.8~150000.1.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.19-race", rpm:"go1.19-race~1.19.8~150000.1.26.1", rls:"SLES15.0SP3"))) {
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
