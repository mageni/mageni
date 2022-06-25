###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for glibc USN-3239-2
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843104");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-03-22 05:49:09 +0100 (Wed, 22 Mar 2017)");
  script_cve_id("CVE-2015-5180", "CVE-2015-8982", "CVE-2015-8983", "CVE-2015-8984",
                "CVE-2016-1234", "CVE-2016-3706", "CVE-2016-4429", "CVE-2016-5417",
                "CVE-2016-6323");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for glibc USN-3239-2");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"USN-3239-1 fixed vulnerabilities in the GNU
  C Library. Unfortunately, the fix for CVE-2015-5180 introduced an internal ABI
  change within the resolver library. This update reverts the change. We apologize
  for the inconvenience. Please note that long-running services that were
  restarted to compensate for the USN-3239-1 update may need to be restarted
  again. Original advisory details: It was discovered that the GNU C Library
  incorrectly handled the strxfrm() function. An attacker could use this issue to
  cause a denial of service or possibly execute arbitrary code. This issue only
  affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2015-8982) It was
  discovered that an integer overflow existed in the _IO_wstr_overflow() function
  of the GNU C Library. An attacker could use this to cause a denial of service or
  possibly execute arbitrary code. This issue only affected Ubuntu 12.04 LTS and
  Ubuntu 14.04 LTS. (CVE-2015-8983) It was discovered that the fnmatch() function
  in the GNU C Library did not properly handle certain malformed patterns. An
  attacker could use this to cause a denial of service. This issue only affected
  Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2015-8984) Alexander Cherepanov
  discovered a stack-based buffer overflow in the glob implementation of the GNU C
  Library. An attacker could use this to specially craft a directory layout and
  cause a denial of service. (CVE-2016-1234) Florian Weimer discovered a NULL
  pointer dereference in the DNS resolver of the GNU C Library. An attacker could
  use this to cause a denial of service. (CVE-2015-5180) Michael Petlan discovered
  an unbounded stack allocation in the getaddrinfo() function of the GNU C
  Library. An attacker could use this to cause a denial of service.
  (CVE-2016-3706) Aldy Hernandez discovered an unbounded stack allocation in the
  sunrpc implementation in the GNU C Library. An attacker could use this to cause
  a denial of service. (CVE-2016-4429) Tim Ruehsen discovered that the
  getaddrinfo() implementation in the GNU C Library did not properly track memory
  allocations. An attacker could use this to cause a denial of service. This issue
  only affected Ubuntu 16.04 LTS. (CVE-2016-5417) Andreas Schwab discovered that
  the GNU C Library on ARM 32-bit platforms did not properly set up execution
  contexts. An attacker could use this to cause a denial of service.
  (CVE-2016-6323)");
  script_tag(name:"affected", value:"glibc on Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3239-2/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS|16\.04 LTS)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libc6:i386", ver:"2.19-0ubuntu6.11", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libc6:amd64", ver:"2.19-0ubuntu6.11", rls:"UBUNTU14.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libc6:i386", ver:"2.15-0ubuntu10.17", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libc6:amd64", ver:"2.15-0ubuntu10.17", rls:"UBUNTU12.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libc6:i386", ver:"2.23-0ubuntu7", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libc6:amd64", ver:"2.23-0ubuntu7", rls:"UBUNTU16.04 LTS")) != NULL)
  {
     security_message(data:res);
     exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}