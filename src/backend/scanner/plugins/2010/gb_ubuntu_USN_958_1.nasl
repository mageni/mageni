###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_958_1.nasl 8274 2018-01-03 07:28:17Z teissa $
#
# Ubuntu Update for thunderbird vulnerabilities USN-958-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "Several flaws were discovered in the browser engine of Thunderbird. If a
  user were tricked into viewing malicious content, a remote attacker could
  use this to crash Thunderbird or possibly run arbitrary code as the user
  invoking the program. (CVE-2010-1211, CVE-2010-1212)

  An integer overflow was discovered in how Thunderbird processed CSS values.
  An attacker could exploit this to crash Thunderbird or possibly run
  arbitrary code as the user invoking the program. (CVE-2010-2752)
  
  An integer overflow was discovered in how Thunderbird interpreted the XUL
  element. If a user were tricked into viewing malicious content, a remote
  attacker could use this to crash Thunderbird or possibly run arbitrary code
  as the user invoking the program. (CVE-2010-2753)
  
  Aki Helin discovered that libpng did not properly handle certain malformed
  PNG images. If a user were tricked into opening a crafted PNG file, an
  attacker could cause a denial of service or possibly execute arbitrary code
  with the privileges of the user invoking the program. (CVE-2010-1205)
  
  Yosuke Hasegawa discovered that the same-origin check in Thunderbird could
  be bypassed by utilizing the importScripts Web Worker method. If a user
  were tricked into viewing malicious content, an attacker could exploit this
  to read data from other domains. (CVE-2010-1213)
  
  Chris Evans discovered that Thunderbird did not properly process improper
  CSS selectors. If a user were tricked into viewing malicious content, an
  attacker could exploit this to read data from other domains.
  (CVE-2010-0654)
  
  Soroush Dalili discovered that Thunderbird did not properly handle script
  error output. An attacker could use this to access URL parameters from
  other domains. (CVE-2010-2754)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-958-1";
tag_affected = "thunderbird vulnerabilities on Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-958-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.314677");
  script_version("$Revision: 8274 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-03 08:28:17 +0100 (Wed, 03 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-07-30 15:25:34 +0200 (Fri, 30 Jul 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0654", "CVE-2010-1205", "CVE-2010-1211", "CVE-2010-1212", "CVE-2010-1213", "CVE-2010-2752", "CVE-2010-2753", "CVE-2010-2754");
  script_name("Ubuntu Update for thunderbird vulnerabilities USN-958-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird-dbg", ver:"3.0.6+build2+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird-dev", ver:"3.0.6+build2+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird-gnome-support-dbg", ver:"3.0.6+build2+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird-gnome-support", ver:"3.0.6+build2+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"3.0.6+build2+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
