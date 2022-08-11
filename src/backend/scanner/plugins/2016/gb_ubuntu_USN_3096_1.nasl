###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for ntp USN-3096-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842905");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-10-06 06:56:04 +0200 (Thu, 06 Oct 2016)");
  script_cve_id("CVE-2015-7973", "CVE-2015-7974", "CVE-2015-7975", "CVE-2015-7976",
		"CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8138",
		"CVE-2015-8158", "CVE-2016-0727", "CVE-2016-1547", "CVE-2016-1548",
		"CVE-2016-1550", "CVE-2016-2516", "CVE-2016-2518", "CVE-2016-4954",
		"CVE-2016-4955", "CVE-2016-4956");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for ntp USN-3096-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Aanchal Malhotra discovered that NTP
  incorrectly handled authenticated broadcast mode. A remote attacker could use
  this issue to perform a replay attack. (CVE-2015-7973)

Matt Street discovered that NTP incorrectly verified peer associations of
symmetric keys. A remote attacker could use this issue to perform an
impersonation attack. (CVE-2015-7974)

Jonathan Gardner discovered that the NTP ntpq utility incorrectly handled
memory. An attacker could possibly use this issue to cause ntpq to crash,
resulting in a denial of service. This issue only affected Ubuntu 16.04
LTS. (CVE-2015-7975)

Jonathan Gardner discovered that the NTP ntpq utility incorrectly handled
dangerous characters in filenames. An attacker could possibly use this
issue to overwrite arbitrary files. (CVE-2015-7976)

Stephen Gray discovered that NTP incorrectly handled large restrict lists.
An attacker could use this issue to cause NTP to crash, resulting in a
denial of service. (CVE-2015-7977, CVE-2015-7978)

Aanchal Malhotra discovered that NTP incorrectly handled authenticated
broadcast mode. A remote attacker could use this issue to cause NTP to
crash, resulting in a denial of service. (CVE-2015-7979)

Jonathan Gardner discovered that NTP incorrectly handled origin timestamp
checks. A remote attacker could use this issue to spoof peer servers.
(CVE-2015-8138)

Jonathan Gardner discovered that the NTP ntpq utility did not properly
handle certain incorrect values. An attacker could possibly use this issue
to cause ntpq to hang, resulting in a denial of service. (CVE-2015-8158)

It was discovered that the NTP cronjob incorrectly cleaned up the
statistics directory. A local attacker could possibly use this to escalate
privileges. (CVE-2016-0727)

Stephen Gray and Matthew Van Gundy discovered that NTP incorrectly
validated crypto-NAKs. A remote attacker could possibly use this issue to
prevent clients from synchronizing. (CVE-2016-1547)

Miroslav Lichvar and Jonathan Gardner discovered that NTP incorrectly
handled switching to interleaved symmetric mode. A remote attacker could
possibly use this issue to prevent clients from synchronizing.
(CVE-2016-1548)

Matthew Van Gundy, Stephen Gray and Loganaden Velvindron discovered that
NTP incorrectly handled message authentication. A remote attacker could
possibly use this issue to recover the message digest key. (CVE-2016-1550)

Yihan Lian discovered that NTP incorrectly handled duplicate IPs on
unconfig directives. An authenticated remote attacker could possibly use
this issue to cause NTP to crash, resulting in a denial of service.
(CVE-2016 ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"ntp on Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3096-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

  if ((res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.6.p5+dfsg-3ubuntu2.14.04.10", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.6.p3+dfsg-1ubuntu3.11", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.8p4+dfsg-3ubuntu5.3", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
