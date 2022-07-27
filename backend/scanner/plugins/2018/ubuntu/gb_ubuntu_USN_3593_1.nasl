###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3593_1.nasl 14288 2019-03-18 16:34:17Z cfischer $
#
# Ubuntu Update for zsh USN-3593-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843682");
  script_version("$Revision: 14288 $");
  script_cve_id("CVE-2014-10070", "CVE-2014-10071", "CVE-2014-10072", "CVE-2016-10714", "CVE-2017-18205", "CVE-2017-18206", "CVE-2018-7548", "CVE-2018-7549");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:06:19 +0200 (Fri, 26 Oct 2018)");
  script_name("Ubuntu Update for zsh USN-3593-1");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|17\.10|16\.04 LTS)");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3593-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zsh'
  package(s) announced via the USN-3593-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Zsh incorrectly handled certain environment
variables. An attacker could possibly use this issue to gain privileged
access to the system. This issue only affected Ubuntu 14.04 LTS.
(CVE-2014-10070)

It was discovered that Zsh incorrectly handled certain inputs.
An attacker could possibly use this to execute arbitrary code. This
issue only affected Ubuntu 14.04 LTS. (CVE-2014-10071)

It was discovered that Zsh incorrectly handled some symbolic links.
An attacker could possibly use this to execute arbitrary code. This
issue only affected Ubuntu 14.04 LTS. (CVE-2014-10072)

It was discovered that Zsh incorrectly handled certain errors. An
attacker could possibly use this issue to cause a denial of service.
(CVE-2016-10714)

It was discovered that Zsh incorrectly handled certain commands. An
attacker could possibly use this to execute arbitrary code.
(CVE-2017-18205)

It was discovered that Zsh incorrectly handled certain symlinks. An
attacker could possibly use this to execute arbitrary code. This issue
only affected Ubuntu 16.04 LTS and Ubuntu 17.10. (CVE-2017-18206)

It was discovered that Zsh incorrectly handled certain inputs. An
attacker could possible use to execute arbitrary code. This issue only
affected Ubuntu 17.10. (CVE-2018-7548)

It was discovered that Zsh incorrectly handled certain inputs. An
attacker could possibly use this to cause a denial of service.
(CVE-2018-7549)");

  script_tag(name:"affected", value:"zsh on Ubuntu 17.10,
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

  if ((res = isdpkgvuln(pkg:"zsh", ver:"5.0.2-3ubuntu6.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU17.10")
{

  if ((res = isdpkgvuln(pkg:"zsh", ver:"5.2-5ubuntu1.1", rls:"UBUNTU17.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"zsh", ver:"5.1.1-1ubuntu2.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
