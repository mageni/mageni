###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for firefox USN-3260-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843135");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-04-22 06:45:04 +0200 (Sat, 22 Apr 2017)");
  script_cve_id("CVE-2017-5429", "CVE-2017-5430", "CVE-2017-5432", "CVE-2017-5433",
                "CVE-2017-5434", "CVE-2017-5435", "CVE-2017-5436", "CVE-2017-5437",
                "CVE-2017-5438", "CVE-2017-5439", "CVE-2017-5440", "CVE-2017-5441",
                "CVE-2017-5442", "CVE-2017-5443", "CVE-2017-5444", "CVE-2017-5445",
                "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5448", "CVE-2017-5449",
                "CVE-2017-5451", "CVE-2017-5453", "CVE-2017-5454", "CVE-2017-5455",
                "CVE-2017-5456", "CVE-2017-5458", "CVE-2017-5459", "CVE-2017-5460",
                "CVE-2017-5461", "CVE-2017-5464", "CVE-2017-5465", "CVE-2017-5466",
                "CVE-2017-5467", "CVE-2017-5468", "CVE-2017-5469", "CVE-2017-5462");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");

  script_name("Ubuntu Update for firefox USN-3260-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in
Firefox. If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit these to read uninitialized memory, obtain
sensitive information, spoof the addressbar contents or other UI elements, escape
the sandbox to read local files, conduct cross-site scripting (XSS)
attacks, cause a denial of service via application crash, or execute
arbitrary code. (CVE-2017-5429, CVE-2017-5430, CVE-2017-5432,
CVE-2017-5433, CVE-2017-5434, CVE-2017-5435, CVE-2017-5436, CVE-2017-5437,
CVE-2017-5438, CVE-2017-5439, CVE-2017-5440, CVE-2017-5441, CVE-2017-5442,
CVE-2017-5443, CVE-2017-5444, CVE-2017-5445, CVE-2017-5446, CVE-2017-5447,
CVE-2017-5448, CVE-2017-5449, CVE-2017-5451, CVE-2017-5453, CVE-2017-5454,
CVE-2017-5455, CVE-2017-5456, CVE-2017-5458, CVE-2017-5459, CVE-2017-5460,
CVE-2017-5461, CVE-2017-5464, CVE-2017-5465, CVE-2017-5466, CVE-2017-5467,
CVE-2017-5468, CVE-2017-5469)

A flaw was discovered in the DRBG number generation in NSS. If an
attacker were able to perform a man-in-the-middle attack, this flaw
could potentially be exploited to view sensitive information.
(CVE-2017-5462)");
  script_tag(name:"affected", value:"firefox on Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS");

  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3260-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|16\.10|16\.04 LTS)");

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

  if ((res = isdpkgvuln(pkg:"firefox", ver:"53.0+build6-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"53.0+build6-0ubuntu0.16.10.1", rls:"UBUNTU16.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"53.0+build6-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
