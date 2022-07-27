###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1500_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for pidgin USN-1500-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1500-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.841076");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-10 10:08:13 +0530 (Tue, 10 Jul 2012)");
  script_cve_id("CVE-2011-4601", "CVE-2011-4602", "CVE-2011-4603", "CVE-2011-4922",
                "CVE-2011-4939", "CVE-2012-1178", "CVE-2012-2214", "CVE-2012-2318",
                "CVE-2012-3374");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ubuntu Update for pidgin USN-1500-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04 LTS|12\.04 LTS|11\.10|11\.04)");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1500-1");
  script_tag(name:"affected", value:"pidgin on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Evgeny Boger discovered that Pidgin incorrectly handled buddy list messages in
  the AIM and ICQ protocol handlers. A remote attacker could send a specially
  crafted message and cause Pidgin to crash, leading to a denial of service. This
  issue only affected Ubuntu 10.04 LTS, 11.04 and 11.10. (CVE-2011-4601)

  Thijs Alkemade discovered that Pidgin incorrectly handled malformed voice and
  video chat requests in the XMPP protocol handler. A remote attacker could send
  a specially crafted message and cause Pidgin to crash, leading to a denial of
  service. This issue only affected Ubuntu 10.04 LTS, 11.04 and 11.10.
  (CVE-2011-4602)

  Diego Bauche Madero discovered that Pidgin incorrectly handled UTF-8
  sequences in the SILC protocol handler. A remote attacker could send a
  specially crafted message and cause Pidgin to crash, leading to a denial
  of service. This issue only affected Ubuntu 10.04 LTS, 11.04 and 11.10.
  (CVE-2011-4603)

  Julia Lawall discovered that Pidgin incorrectly cleared memory contents used in
  cryptographic operations. An attacker could exploit this to read the memory
  contents, leading to an information disclosure. This issue only affected Ubuntu
  10.04 LTS. (CVE-2011-4922)

  Clemens Huebner and Kevin Stange discovered that Pidgin incorrectly handled
  nickname changes inside chat rooms in the XMPP protocol handler. A remote
  attacker could exploit this by changing nicknames, leading to a denial of
  service. This issue only affected Ubuntu 11.10. (CVE-2011-4939)

  Thijs Alkemade discovered that Pidgin incorrectly handled off-line instant
  messages in the MSN protocol handler. A remote attacker could send a specially
  crafted message and cause Pidgin to crash, leading to a denial of service. This
  issue only affected Ubuntu 10.04 LTS, 11.04 and 11.10. (CVE-2012-1178)

  Jose Valentin Gutierrez discovered that Pidgin incorrectly handled SOCKS5 proxy
  connections during file transfer requests in the XMPP protocol handler. A
  remote attacker could send a specially crafted request and cause Pidgin to
  crash, leading to a denial of service. This issue only affected Ubuntu 12.04
  LTS and 11.10. (CVE-2012-2214)

  Fabian Yamaguchi discovered that Pidgin incorrectly handled malformed messages
  in the MSN protocol handler. A remote attacker could send a specially crafted
  message and cause Pidgin to crash, leading to a denial of service.
  (CVE-2012-2318)

  Ulf Harnhammar discovered that Pidgin incorrectly handled messages with in-line
  images in the MXit protocol handler. A remote attacker could send a specially
  crafted message and possibly execute arbitrary code with user privileges.
  (CVE-2012-3374)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"finch", ver:"2.6.6-1ubuntu4.5", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpurple0", ver:"2.6.6-1ubuntu4.5", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin", ver:"2.6.6-1ubuntu4.5", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"finch", ver:"2.10.3-0ubuntu1.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpurple0", ver:"2.10.3-0ubuntu1.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin", ver:"2.10.3-0ubuntu1.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"finch", ver:"2.10.0-0ubuntu2.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpurple0", ver:"2.10.0-0ubuntu2.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin", ver:"2.10.0-0ubuntu2.1", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"finch", ver:"2.7.11-1ubuntu2.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpurple0", ver:"2.7.11-1ubuntu2.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"pidgin", ver:"2.7.11-1ubuntu2.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
