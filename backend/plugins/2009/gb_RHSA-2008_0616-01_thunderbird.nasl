###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for thunderbird RHSA-2008:0616-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Mozilla Thunderbird is a standalone mail and newsgroup client.

  Multiple flaws were found in the processing of malformed JavaScript
  content. An HTML mail containing such malicious content could cause
  Thunderbird to crash or, potentially, execute arbitrary code as the user
  running Thunderbird. (CVE-2008-2801, CVE-2008-2802, CVE-2008-2803)
  
  Several flaws were found in the processing of malformed HTML content. An
  HTML mail containing malicious content could cause Thunderbird to crash or,
  potentially, execute arbitrary code as the user running Thunderbird.
  (CVE-2008-2785, CVE-2008-2798, CVE-2008-2799, CVE-2008-2811)
  
  Several flaws were found in the way malformed HTML content was displayed.
  An HTML mail containing specially-crafted content could, potentially, trick
  a Thunderbird user into surrendering sensitive information. (CVE-2008-2800)
  
  Two local file disclosure flaws were found in Thunderbird. An HTML mail
  containing malicious content could cause Thunderbird to reveal the contents
  of a local file to a remote attacker. (CVE-2008-2805, CVE-2008-2810)
  
  A flaw was found in the way a malformed .properties file was processed by
  Thunderbird. A malicious extension could read uninitialized memory,
  possibly leaking sensitive data to the extension. (CVE-2008-2807)
  
  A flaw was found in the way Thunderbird escaped a listing of local file
  names. If a user could be tricked into listing a local directory containing
  malicious file names, arbitrary JavaScript could be run with the
  permissions of the user running Thunderbird. (CVE-2008-2808)
  
  A flaw was found in the way Thunderbird displayed information about
  self-signed certificates. It was possible for a self-signed certificate to
  contain multiple alternate name entries, which were not all displayed to
  the user, allowing them to mistakenly extend trust to an unknown site.
  (CVE-2008-2809)
  
  Note: JavaScript support is disabled by default in Thunderbird. The above
  issues are not exploitable unless JavaScript is enabled.
  
  All Thunderbird users should upgrade to these updated packages, which
  contain backported patches to resolve these issues.";

tag_affected = "thunderbird on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-July/msg00026.html");
  script_oid("1.3.6.1.4.1.25623.1.0.309029");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2008:0616-01");
  script_cve_id("CVE-2008-2785", "CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2800", "CVE-2008-2801", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2805", "CVE-2008-2807", "CVE-2008-2808", "CVE-2008-2809", "CVE-2008-2810", "CVE-2008-2811");
  script_name( "RedHat Update for thunderbird RHSA-2008:0616-01");

  script_tag(name:"summary", value:"Check for the Version of thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~1.5.0.12~14.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"thunderbird-debuginfo", rpm:"thunderbird-debuginfo~1.5.0.12~14.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
