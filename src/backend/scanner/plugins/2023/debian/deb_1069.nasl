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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2006.1069");
  script_cve_id("CVE-2003-0984", "CVE-2004-0138", "CVE-2004-0394", "CVE-2004-0427", "CVE-2004-0447", "CVE-2004-0554", "CVE-2004-0565", "CVE-2004-0685", "CVE-2004-0883", "CVE-2004-0949", "CVE-2004-0997", "CVE-2004-1016", "CVE-2004-1017", "CVE-2004-1068", "CVE-2004-1070", "CVE-2004-1071", "CVE-2004-1072", "CVE-2004-1073", "CVE-2004-1074", "CVE-2004-1234", "CVE-2004-1235", "CVE-2004-1333", "CVE-2004-1335", "CVE-2005-0001", "CVE-2005-0003", "CVE-2005-0124", "CVE-2005-0384", "CVE-2005-0489", "CVE-2005-0504");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1069)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-1069");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1069");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kernel-source-2.4.18' package(s) announced via the DSA-1069 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local and remote vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2004-0427

A local denial of service vulnerability in do_fork() has been found.

CVE-2005-0489

A local denial of service vulnerability in proc memory handling has been found.

CVE-2004-0394

A buffer overflow in the panic handling code has been found.

CVE-2004-0447

A local denial of service vulnerability through a null pointer dereference in the IA64 process handling code has been found.

CVE-2004-0554

A local denial of service vulnerability through an infinite loop in the signal handler code has been found.

CVE-2004-0565

An information leak in the context switch code has been found on the IA64 architecture.

CVE-2004-0685

Unsafe use of copy_to_user in USB drivers may disclose sensitive information.

CVE-2005-0001

A race condition in the i386 page fault handler may allow privilege escalation.

CVE-2004-0883

Multiple vulnerabilities in the SMB filesystem code may allow denial of service or information disclosure.

CVE-2004-0949

An information leak discovered in the SMB filesystem code.

CVE-2004-1016

A local denial of service vulnerability has been found in the SCM layer.

CVE-2004-1333

An integer overflow in the terminal code may allow a local denial of service vulnerability.

CVE-2004-0997

A local privilege escalation in the MIPS assembly code has been found.

CVE-2004-1335

A memory leak in the ip_options_get() function may lead to denial of service.

CVE-2004-1017

Multiple overflows exist in the io_edgeport driver which might be usable as a denial of service attack vector.

CVE-2005-0124

Bryan Fulton reported a bounds checking bug in the coda_pioctl function which may allow local users to execute arbitrary code or trigger a denial of service attack.

CVE-2003-0984

Inproper initialization of the RTC may disclose information.

CVE-2004-1070

Insufficient input sanitising in the load_elf_binary() function may lead to privilege escalation.

CVE-2004-1071

Incorrect error handling in the binfmt_elf loader may lead to privilege escalation.

CVE-2004-1072

A buffer overflow in the binfmt_elf loader may lead to privilege escalation or denial of service.

CVE-2004-1073

The open_exec function may disclose information.

CVE-2004-1074

The binfmt code is vulnerable to denial of service through malformed a.out binaries.

CVE-2004-0138

A denial of service vulnerability in the ELF loader has been found.

CVE-2004-1068

A programming error in the unix_dgram_recvmsg() function may lead to privilege escalation.

CVE-2004-1234

The ELF loader is vulnerable to denial of service through malformed binaries.

CVE-2005-0003

Crafted ELF binaries may lead to privilege escalation, due to insufficient checking of overlapping memory ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-source-2.4.18' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"kernel-doc-2.4.18", ver:"2.4.18-14.4", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-source-2.4.18", ver:"2.4.18-14.4", rls:"DEB3.0"))) {
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
