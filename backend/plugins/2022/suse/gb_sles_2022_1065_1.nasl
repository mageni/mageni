# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1065.1");
  script_cve_id("CVE-2021-0066", "CVE-2021-0071", "CVE-2021-0072", "CVE-2021-0076", "CVE-2021-0161", "CVE-2021-0164", "CVE-2021-0165", "CVE-2021-0166", "CVE-2021-0168", "CVE-2021-0170", "CVE-2021-0172", "CVE-2021-0173", "CVE-2021-0174", "CVE-2021-0175", "CVE-2021-0176", "CVE-2021-0183", "CVE-2021-33139", "CVE-2021-33155");
  script_tag(name:"creation_date", value:"2022-03-31 13:30:26 +0000 (Thu, 31 Mar 2022)");
  script_version("2022-03-31T13:30:26+0000");
  script_tag(name:"last_modification", value:"2022-04-01 10:07:02 +0000 (Fri, 01 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-21 14:50:00 +0000 (Sun, 21 Nov 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1065-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1065-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221065-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-firmware' package(s) announced via the SUSE-SU-2022:1065-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware fixes the following issues:

Update Intel Wireless firmware for 9xxx (INTEL-SA-00539, bsc#1196333):

CVE-2021-0161: Improper input validation in firmware for Intel PROSet/Wireless Wi-Fi and Killer Wi-Fi may allow a privileged user to potentially enable escalation of privilege via local access.
CVE-2021-0164: Improper access control in firmware for Intel PROSet/Wireless Wi-Fi and Killer Wi-Fi may allow an unauthenticated user to potentially enable escalation of privilege via local access.
CVE-2021-0165: Improper input validation in firmware for Intel PROSet/Wireless Wi-Fi and Killer Wi-Fi may allow an unauthenticated user to potentially enable denial of service via adjacent access.
CVE-2021-0066: Improper input validation in firmware for Intel PROSet/Wireless Wi-Fi and Killer Wi-Fi may allow an unauthenticated user to potentially enable escalation of privilege via local access.
CVE-2021-0166: Exposure of Sensitive Information to an Unauthorized Actor in firmware for some Intel PROSet/Wireless Wi-Fi and some Killer Wi-Fi may allow a privileged user to potentially enable escalation of privilege via local access. CVE-2021-0168: Improper input validation in firmware for some Intel PROSet/Wireless Wi-Fi and some Killer Wi-Fi may allow a privileged user to potentially enable escalation of privilege via local access. CVE-2021-0170: Exposure of Sensitive Information to an Unauthorized Actor in firmware for some Intel PROSet/Wireless Wi-Fi and some Killer Wi-Fi may allow an authenticated user to potentially enable information disclosure via local access. CVE-2021-0172: Improper input validation in firmware for some Intel PROSet/Wireless Wi-Fi and some Killer Wi-Fi may allow an unauthenticated user to potentially enable denial of service via adjacent access. CVE-2021-0173: Improper Validation of Consistency within input in firmware for some Intel PROSet/Wireless Wi-Fi and some Killer Wi-Fi may allow a unauthenticated user to potentially enable denial of service via adjacent access. CVE-2021-0174:
Improper Use of Validation Framework in firmware for some Intel PROSet/Wireless Wi-Fi and some Killer Wi-Fi may allow a unauthenticated user to potentially enable denial of service via adjacent access.
CVE-2021-0175: Improper Validation of Specified Index, Position, or Offset in Input in firmware for some Intel PROSet/Wireless Wi-Fi and some Killer Wi-Fi may allow an unauthenticated user to potentially enable denial of service via adjacent access. CVE-2021-0076: Improper Validation of Specified Index, Position, or Offset in Input in firmware for some Intel PROSet/Wireless Wi-Fi and some Killer Wi-Fi may allow a privileged user to potentially enable denial of service via local access. CVE-2021-0176:
Improper input validation in firmware for some Intel PROSet/Wireless Wi-Fi and some Killer Wi-Fi may allow a privileged user to potentially enable denial of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-firmware' package(s) on SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Module for Basesystem 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~20210208~150300.4.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-brcm", rpm:"kernel-firmware-brcm~20210208~150300.4.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-amd", rpm:"ucode-amd~20210208~150300.4.7.1", rls:"SLES15.0SP3"))) {
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
