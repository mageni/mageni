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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0435");
  script_cve_id("CVE-2018-15127", "CVE-2018-20019", "CVE-2018-20020", "CVE-2018-20021", "CVE-2018-20022", "CVE-2018-20023", "CVE-2018-20024", "CVE-2018-20748", "CVE-2018-20749", "CVE-2018-20750", "CVE-2018-7225", "CVE-2019-15681");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-23 13:15:00 +0000 (Fri, 23 Oct 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0435)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0435");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0435.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27404");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4547-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4587-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'italc' package(s) announced via the MGASA-2020-0435 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in LibVNCServer through 0.9.11.
rfbProcessClientNormalMessage() in rfbserver.c does not sanitize msg.cct.length,
leading to access to uninitialized and potentially sensitive data or possibly
unspecified other impact (e.g., an integer overflow) via specially crafted
VNC packets. (CVE-2018-7225)

LibVNC before commit 502821828ed00b4a2c4bef90683d0fd88ce495de contains heap
out-of-bound write vulnerability in server code of file transfer extension that
can result remote code execution. (CVE-2018-15127)

LibVNC before commit a83439b9fbe0f03c48eb94ed05729cb016f8b72f contains multiple
heap out-of-bound write vulnerabilities in VNC client code that can result
remote code execution. (CVE-2018-20019)

LibVNC before commit 7b1ef0ffc4815cab9a96c7278394152bdc89dc4d contains heap
out-of-bound write vulnerability inside structure in VNC client code that can
result remote code execution. (CVE-2018-20020)

LibVNC before commit c3115350eb8bb635d0fdb4dbbb0d0541f38ed19c contains a CWE-835:
Infinite loop vulnerability in VNC client code. Vulnerability allows attacker
to consume excessive amount of resources like CPU and RAM. (CVE-2018-20021)

LibVNC before 2f5b2ad1c6c99b1ac6482c95844a84d66bb52838 contains multiple
weaknesses CWE-665: Improper Initialization vulnerability in VNC client code
that allows attacker to read stack memory and can be abuse for information
disclosure. Combined with another vulnerability, it can be used to leak stack
memory layout and in bypassing ASLR. (CVE-2018-20022)

LibVNC before 8b06f835e259652b0ff026898014fc7297ade858 contains CWE-665:
Improper Initialization vulnerability in VNC Repeater client code that allows
attacker to read stack memory and can be abuse for information disclosure.
Combined with another vulnerability, it can be used to leak stack memory layout
and in bypassing ASLR. (CVE-2018-20023)

LibVNC before commit 4a21bbd097ef7c44bb000c3bd0907f96a10e4ce7 contains null
pointer dereference in VNC client code that can result DoS. (CVE-2018-20024)

LibVNC before 0.9.12 contains multiple heap out-of-bounds write vulnerabilities
in libvncclient/rfbproto.c. The fix for CVE-2018-20019 was incomplete.
(CVE-2018-20748)

LibVNC before 0.9.12 contains a heap out-of-bounds write vulnerability in
libvncserver/rfbserver.c. The fix for CVE-2018-15127 was incomplete.
(CVE-2018-20749)

LibVNC through 0.9.12 contains a heap out-of-bounds write vulnerability in
libvncserver/rfbserver.c. The fix for CVE-2018-15127 was incomplete.
(CVE-2018-20750)

LibVNC commit before d01e1bb4246323ba6fcee3b82ef1faa9b1dac82a contains a
memory leak (CWE-655) in VNC server code, which allow an attacker to read
stack memory and can be abused for information disclosure. Combined with
another vulnerability, it can be used to leak stack memory and bypass ASLR.
This attack appear to be exploitable via network connectivity.
(CVE-2019-15681)");

  script_tag(name:"affected", value:"'italc' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"italc", rpm:"italc~3.0.3~3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"italc-client", rpm:"italc-client~3.0.3~3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"italc-client-autostart", rpm:"italc-client-autostart~3.0.3~3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"italc-master", rpm:"italc-master~3.0.3~3.1.mga7", rls:"MAGEIA7"))) {
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
