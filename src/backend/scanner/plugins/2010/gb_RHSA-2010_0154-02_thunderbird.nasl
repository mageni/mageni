###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for thunderbird RHSA-2010:0154-02
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
tag_insight = "Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several flaws were found in the processing of malformed HTML mail content.
  An HTML mail message containing malicious content could cause Thunderbird
  to crash or, potentially, execute arbitrary code with the privileges of the
  user running Thunderbird. (CVE-2009-2462, CVE-2009-2463, CVE-2009-2466,
  CVE-2009-3072, CVE-2009-3075, CVE-2009-3380, CVE-2009-3979, CVE-2010-0159)
  
  A use-after-free flaw was found in Thunderbird. An attacker could use this
  flaw to crash Thunderbird or, potentially, execute arbitrary code with the
  privileges of the user running Thunderbird. (CVE-2009-3077)
  
  A heap-based buffer overflow flaw was found in the Thunderbird string to
  floating point conversion routines. An HTML mail message containing
  malicious JavaScript could crash Thunderbird or, potentially, execute
  arbitrary code with the privileges of the user running Thunderbird.
  (CVE-2009-0689)
  
  A use-after-free flaw was found in Thunderbird. Under low memory
  conditions, viewing an HTML mail message containing malicious content could
  result in Thunderbird executing arbitrary code with the privileges of the
  user running Thunderbird. (CVE-2009-1571)
  
  A flaw was found in the way Thunderbird created temporary file names for
  downloaded files. If a local attacker knows the name of a file Thunderbird
  is going to download, they can replace the contents of that file with
  arbitrary contents. (CVE-2009-3274)
  
  A flaw was found in the way Thunderbird displayed a right-to-left override
  character when downloading a file. In these cases, the name displayed in
  the title bar differed from the name displayed in the dialog body. An
  attacker could use this flaw to trick a user into downloading a file that
  has a file name or extension that is different from what the user expected.
  (CVE-2009-3376)
  
  A flaw was found in the way Thunderbird processed SOCKS5 proxy replies. A
  malicious SOCKS5 server could send a specially-crafted reply that would
  cause Thunderbird to crash. (CVE-2009-2470)
  
  Descriptions in the dialogs when adding and removing PKCS #11 modules were
  not informative. An attacker able to trick a user into installing a
  malicious PKCS #11 module could use this flaw to install their own
  Certificate Authority certificates on a user's machine, making it possible
  to trick the user into believing they are viewing trusted content or,
  potentially, execute arbitrary code with the privi ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "thunderbird on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-March/msg00016.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313706");
  script_version("$Revision: 8269 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-02 08:28:22 +0100 (Tue, 02 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-22 11:34:53 +0100 (Mon, 22 Mar 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2010:0154-02");
  script_cve_id("CVE-2009-1571", "CVE-2009-3076", "CVE-2009-3075", "CVE-2009-3072", "CVE-2009-0689", "CVE-2009-3077", "CVE-2009-3380", "CVE-2010-0159", "CVE-2009-3979", "CVE-2009-3274", "CVE-2009-2463", "CVE-2009-2462", "CVE-2009-2470", "CVE-2009-2466", "CVE-2009-3376");
  script_name("RedHat Update for thunderbird RHSA-2010:0154-02");

  script_tag(name: "summary" , value: "Check for the Version of thunderbird");
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

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~1.5.0.12~25.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"thunderbird-debuginfo", rpm:"thunderbird-debuginfo~1.5.0.12~25.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
