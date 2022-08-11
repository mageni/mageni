###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3271_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for libxslt USN-3271-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843148");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-04-29 07:16:29 +0200 (Sat, 29 Apr 2017)");
  script_cve_id("CVE-2017-5029", "CVE-2016-1683", "CVE-2016-1841", "CVE-2015-7995",
                "CVE-2016-1684", "CVE-2016-4738");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for libxslt USN-3271-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxslt'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Holger Fuhrmannek discovered an integer
overflow in the xsltAddTextString() function in Libxslt. An attacker could use
this to craft a malicious document that, when opened, could cause a
denial of service (application crash) or possible execute arbitrary
code. (CVE-2017-5029)

Nicolas Gregoire discovered that Libxslt mishandled namespace
nodes. An attacker could use this to craft a malicious document that,
when opened, could cause a denial of service (application crash)
or possibly execute arbtrary code. This issue only affected Ubuntu
16.04 LTS, Ubuntu 14.04 LTS, and Ubuntu 12.04 LTS. (CVE-2016-1683)

Sebastian Apelt discovered that a use-after-error existed in the
xsltDocumentFunctionLoadDocument() function in Libxslt. An attacker
could use this to craft a malicious document that, when opened,
could cause a denial of service (application crash) or possibly
execute arbitrary code. This issue only affected Ubuntu 16.04 LTS,
Ubuntu 14.04 LTS, and Ubuntu 12.04 LTS. (CVE-2016-1841)

It was discovered that a type confusion error existed in the
xsltStylePreCompute() function in Libxslt. An attacker could use this
to craft a malicious XML file that, when opened, caused a denial of
service (application crash). This issue only affected Ubuntu 14.04
LTS and Ubuntu 12.04 LTS. (CVE-2015-7995)

Nicolas Gregoire discovered the Libxslt mishandled the 'i' and 'a'
format tokens for xsl:number data. An attacker could use this to
craft a malicious document that, when opened, could cause a denial of
service (application crash). This issue only affected Ubuntu 16.04 LTS,
Ubuntu 14.04 LTS, and Ubuntu 12.04 LTS. (CVE-2016-1684)

It was discovered that the xsltFormatNumberConversion() function
in Libxslt did not properly handle empty decimal separators. An
attacker could use this to craft a malicious document that, when
opened, could cause a denial of service (application crash). This
issue only affected Ubuntu 16.10, Ubuntu 16.04 LTS, Ubuntu 14.04 LTS,
and Ubuntu 12.04 LTS. (CVE-2016-4738)");
  script_tag(name:"affected", value:"libxslt on Ubuntu 17.04,
  Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3271-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|17\.04|12\.04 LTS|16\.10|16\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"libxslt1.1:amd64", ver:"1.1.28-2ubuntu0.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxslt1.1:i386", ver:"1.1.28-2ubuntu0.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU17.04")
{

  if ((res = isdpkgvuln(pkg:"libxslt1.1:amd64", ver:"1.1.29-2ubuntu0.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxslt1.1:i386", ver:"1.1.29-2ubuntu0.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libxslt1.1:amd64", ver:"1.1.26-8ubuntu1.4", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxslt1.1:i386", ver:"1.1.26-8ubuntu1.4", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.10")
{

  if ((res = isdpkgvuln(pkg:"libxslt1.1:amd64", ver:"1.1.29-1ubuntu0.1", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxslt1.1:i386", ver:"1.1.29-1ubuntu0.1", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }


  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libxslt1.1:amd64", ver:"1.1.28-2.1ubuntu0.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxslt1.1:i386", ver:"1.1.28-2.1ubuntu0.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
