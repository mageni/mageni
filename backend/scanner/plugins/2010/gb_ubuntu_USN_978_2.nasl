###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_978_2.nasl 8287 2018-01-04 07:28:11Z teissa $
#
# Ubuntu Update for thunderbird regression USN-978-2
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
tag_insight = "USN-978-1 fixed vulnerabilities in Thunderbird. Some users reported
  stability problems under certain circumstances. This update fixes the
  problem.

  We apologize for the inconvenience.

  Original advisory details:

  Several dangling pointer vulnerabilities were discovered in Thunderbird. An
  attacker could exploit this to crash Thunderbird or possibly run arbitrary
  code as the user invoking the program. (CVE-2010-2760, CVE-2010-2767,
  CVE-2010-3167)

  It was discovered that the XPCSafeJSObjectWrapper (SJOW) security wrapper
  did not always honor the same-origin policy. If JavaScript was enabled, an
  attacker could exploit this to run untrusted JavaScript from other domains.
  (CVE-2010-2763)
  
  Matt Haggard discovered that Thunderbird did not honor same-origin policy
  when processing the statusText property of an XMLHttpRequest object. If a
  user were tricked into viewing a malicious site, a remote attacker could
  use this to gather information about servers on internal private networks.
  (CVE-2010-2764)
  
  Chris Rohlf discovered an integer overflow when Thunderbird processed the
  HTML frameset element. If a user were tricked into viewing a malicious
  site, a remote attacker could use this to crash Thunderbird or possibly run
  arbitrary code as the user invoking the program. (CVE-2010-2765)
  
  Several issues were discovered in the browser engine. If a user were
  tricked into viewing a malicious site, a remote attacker could use this to
  crash Thunderbird or possibly run arbitrary code as the user invoking the
  program. (CVE-2010-2766, CVE-2010-3168)
  
  David Huang and Collin Jackson discovered that the &lt;object&gt; tag could
  override the charset of a framed HTML document in another origin. An
  attacker could utilize this to perform cross-site scripting attacks.
  (CVE-2010-2768)
  
  Paul Stone discovered that with designMode enabled an HTML selection
  containing JavaScript could be copied and pasted into a document and have
  the JavaScript execute within the context of the site where the code was
  dropped. If JavaScript was enabled, an attacker could utilize this to
  perform cross-site scripting attacks. (CVE-2010-2769)
  
  A buffer overflow was discovered in Thunderbird when processing text runs.
  If a user were tricked into viewing a malicious site, a remote attacker
  could use this to crash Thunderbird or possibly run arbitrary code as the
  user invoking the program. (CVE-2010-3166)
  
  Peter Van der Beken, Jason Oster, Jesse Ruderman, Igor Bukanov, Jeff
  Walden, Gary Kwong and Olli Pettay discovered several flaws i ... 

  Description truncated, for more information please check the Reference URL";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-978-2";
tag_affected = "thunderbird regression on Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-978-2/");
  script_oid("1.3.6.1.4.1.25623.1.0.313911");
  script_version("$Revision: 8287 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 08:28:11 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-22 08:32:53 +0200 (Wed, 22 Sep 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2760", "CVE-2010-2767", "CVE-2010-3167", "CVE-2010-2763", "CVE-2010-2764", "CVE-2010-2765", "CVE-2010-2766", "CVE-2010-3168", "CVE-2010-2768", "CVE-2010-2769", "CVE-2010-3166", "CVE-2010-3169");
  script_name("Ubuntu Update for thunderbird regression USN-978-2");

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

  if ((res = isdpkgvuln(pkg:"thunderbird-dbg", ver:"3.0.8+build2+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird-dev", ver:"3.0.8+build2+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird-gnome-support-dbg", ver:"3.0.8+build2+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird-gnome-support", ver:"3.0.8+build2+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"3.0.8+build2+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
