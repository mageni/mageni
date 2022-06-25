###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for irssi USN-3184-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843030");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-02-03 12:11:07 +0530 (Fri, 03 Feb 2017)");
  script_cve_id("CVE-2016-7553", "CVE-2017-5193", "CVE-2017-5194", "CVE-2017-5195",
		"CVE-2017-5196", "CVE-2017-5356");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for irssi USN-3184-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'irssi'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"It was discovered that the Irssi buf.pl script set incorrect permissions. A
local attacker could use this issue to retrieve another user's window
contents. (CVE-2016-7553)

Joseph Bisch discovered that Irssi incorrectly handled comparing nicks. A
remote attacker could use this issue to cause Irssi to crash, resulting in
a denial of service, or possibly execute arbitrary code. (CVE-2017-5193)

It was discovered that Irssi incorrectly handled invalid nick messages. A
remote attacker could use this issue to cause Irssi to crash, resulting in
a denial of service, or possibly execute arbitrary code. (CVE-2017-5194)

Joseph Bisch discovered that Irssi incorrectly handled certain incomplete
control codes. A remote attacker could use this issue to cause Irssi to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 16.04 LTS and Ubuntu 16.10.
(CVE-2017-5195)

Hanno B&#246 ck and Joseph Bisch discovered that Irssi incorrectly handled
certain incomplete character sequences. A remote attacker could use this
issue to cause Irssi to crash, resulting in a denial of service. This issue
only affected Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2017-5196)

Hanno B&#246 ck discovered that Irssi incorrectly handled certain format
strings. A remote attacker could use this issue to cause Irssi to crash,
resulting in a denial of service. (CVE-2017-5356)");
  script_tag(name:"affected", value:"irssi on Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3184-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|16\.10|12\.04 LTS|16\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"irssi", ver:"0.8.15-5ubuntu3.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.10")
{

  if ((res = isdpkgvuln(pkg:"irssi", ver:"0.8.19-1ubuntu2.1", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"irssi", ver:"0.8.15-4ubuntu3.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"irssi", ver:"0.8.19-1ubuntu1.3", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
