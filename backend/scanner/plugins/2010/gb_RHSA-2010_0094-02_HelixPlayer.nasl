###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for HelixPlayer RHSA-2010:0094-02
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
tag_insight = "HelixPlayer is a media player.

  Multiple buffer and integer overflow flaws were found in the way
  HelixPlayer processed Graphics Interchange Format (GIF) files. An attacker
  could create a specially-crafted GIF file which would cause HelixPlayer to
  crash or, potentially, execute arbitrary code when opened. (CVE-2009-4242,
  CVE-2009-4245)
  
  A buffer overflow flaw was found in the way HelixPlayer processed
  Synchronized Multimedia Integration Language (SMIL) files. An attacker
  could create a specially-crafted SMIL file which would cause HelixPlayer to
  crash or, potentially, execute arbitrary code when opened. (CVE-2009-4257)
  
  A buffer overflow flaw was found in the way HelixPlayer handled the Real
  Time Streaming Protocol (RTSP) SET_PARAMETER directive. A malicious RTSP
  server could use this flaw to crash HelixPlayer or, potentially, execute
  arbitrary code. (CVE-2009-4248)
  
  Multiple buffer overflow flaws were discovered in the way HelixPlayer
  handled RuleBook structures in media files and RTSP streams.
  Specially-crafted input could cause HelixPlayer to crash or, potentially,
  execute arbitrary code. (CVE-2009-4247, CVE-2010-0417)
  
  A buffer overflow flaw was found in the way HelixPlayer performed URL
  un-escaping. A specially-crafted URL string could cause HelixPlayer to
  crash or, potentially, execute arbitrary code. (CVE-2010-0416)
  
  All HelixPlayer users are advised to upgrade to this updated package,
  which contains backported patches to resolve these issues. All running
  instances of HelixPlayer must be restarted for this update to take effect.";

tag_affected = "HelixPlayer on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-February/msg00003.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313836");
  script_version("$Revision: 8495 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 08:57:49 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-02-15 16:07:49 +0100 (Mon, 15 Feb 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2010:0094-02");
  script_cve_id("CVE-2009-4242", "CVE-2009-4245", "CVE-2009-4247", "CVE-2009-4248", "CVE-2009-4257", "CVE-2010-0416", "CVE-2010-0417");
  script_name("RedHat Update for HelixPlayer RHSA-2010:0094-02");

  script_tag(name: "summary" , value: "Check for the Version of HelixPlayer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"HelixPlayer", rpm:"HelixPlayer~1.0.6~1.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"HelixPlayer-debuginfo", rpm:"HelixPlayer-debuginfo~1.0.6~1.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
