###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3199_2.nasl 14288 2019-03-18 16:34:17Z cfischer $
#
# Ubuntu Update for python-crypto USN-3199-2
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.843703");
  script_version("$Revision: 14288 $");
  script_cve_id("CVE-2013-7459");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:08:49 +0200 (Fri, 26 Oct 2018)");
  script_name("Ubuntu Update for python-crypto USN-3199-2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|16\.10|16\.04 LTS)");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3199-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-crypto'
  package(s) announced via the USN-3199-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3199-1 fixed a vulnerability in the Python Cryptography Toolkit.
Unfortunately, various programs depended on the original behavior of the Python
Cryptography Toolkit which was altered when fixing the vulnerability. This
update retains the fix for the vulnerability but issues a warning rather than
throwing an exception. Code which produces this warning should be updated
because future versions of the Python Cryptography Toolkit re-introduce the
exception.

We apologize for the inconvenience.

Original advisory details:

&#160 It was discovered that the ALGnew function in block_template.c in the Python
&#160 Cryptography Toolkit contained a heap-based buffer overflow vulnerability.
&#160 A remote attacker could use this flaw to execute arbitrary code by using
&#160 a crafted initialization vector parameter.");

  script_tag(name:"affected", value:"python-crypto on Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"python-crypto", ver:"2.6.1-4ubuntu0.2", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python3-crypto", ver:"2.6.1-4ubuntu0.2", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.10")
{

  if ((res = isdpkgvuln(pkg:"python-crypto", ver:"2.6.1-6ubuntu0.16.10.3", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python3-crypto", ver:"2.6.1-6ubuntu0.16.10.3", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"python-crypto", ver:"2.6.1-6ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python3-crypto", ver:"2.6.1-6ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
