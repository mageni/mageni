###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for binutils USN-2496-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842088");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-02-10 05:30:54 +0100 (Tue, 10 Feb 2015)");
  script_cve_id("CVE-2014-8485", "CVE-2014-8501", "CVE-2014-8502", "CVE-2014-8737",
                "CVE-2014-8738", "CVE-2014-8503", "CVE-2014-8504", "CVE-2014-8484",
                "CVE-2012-3509");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for binutils USN-2496-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Michal Zalewski discovered that the
setup_group function in libbfd in GNU binutils did not properly check group
headers in ELF files. An attacker could use this to craft input that could
cause a denial of service (application crash) or possibly execute arbitrary code.
(CVE-2014-8485)
Hanno B&#246 ck discovered that the _bfd_XXi_swap_aouthdr_in function
in libbfd in GNU binutils allowed out-of-bounds writes. An
attacker could use this to craft input that could cause a denial
of service (application crash) or possibly execute arbitrary code.
(CVE-2014-8501)

Hanno B&#246 ck discovered a heap-based buffer overflow in the
pe_print_edata function in libbfd in GNU binutils. An attacker
could use this to craft input that could cause a denial of service
(application crash) or possibly execute arbitrary code. (CVE-2014-8502)

Alexander Cherepanov discovered multiple directory traversal
vulnerabilities in GNU binutils. An attacker could use this to craft
input that could delete arbitrary files. (CVE-2014-8737)

Alexander Cherepanov discovered the _bfd_slurp_extended_name_table
function in libbfd in GNU binutils allowed invalid writes when handling
extended name tables in an archive. An attacker could use this to
craft input that could cause a denial of service (application crash)
or possibly execute arbitrary code. (CVE-2014-8738)

Hanno B&#246 ck discovered a stack-based buffer overflow in the ihex_scan
function in libbfd in GNU binutils. An attacker could use this
to craft input that could cause a denial of service (application
crash). (CVE-2014-8503)

Michal Zalewski discovered a stack-based buffer overflow in the
srec_scan function in libbfd in GNU binutils. An attacker could
use this to to craft input that could cause a denial of service
(application crash)  the GNU C library's Fortify Source printf
protection should prevent the possibility of executing arbitrary code.
(CVE-2014-8504)

Michal Zalewski discovered that the srec_scan function in libbfd
in GNU binutils allowed out-of-bounds reads. An attacker could
use this to craft input to cause a denial of service. This issue
only affected Ubuntu 14.04 LTS, Ubuntu 12.04 LTS, and Ubuntu 10.04
LTS. (CVE-2014-8484)

Sang Kil Cha discovered multiple integer overflows in the
_objalloc_alloc function and objalloc_alloc macro in binutils. This
could allow an attacker to cause a denial of service (application
crash). This issue only affected Ubuntu 12.04 LTS and Ubuntu 10.04 LTS.
(CVE-2012-3509)

Alexander Cherepanov and Hanno B&#246 ck discovered multiple additional
out-of-bounds reads and w ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"binutils on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2496-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.10|14\.04 LTS|12\.04 LTS|10\.04 LTS)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.10")
{

  if ((res = isdpkgvuln(pkg:"binutils", ver:"2.24.90.20141014-0ubuntu3.1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.24.90.20141014-0ubuntu3.1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"binutils", ver:"2.24-5ubuntu3.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.24-5ubuntu3.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"binutils", ver:"2.22-6ubuntu1.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.22-6ubuntu1.2", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"binutils", ver:"2.20.1-3ubuntu7.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.20.1-3ubuntu7.2", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
