###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for sendmail RHSA-2010:0237-05
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
tag_insight = "Sendmail is a very widely used Mail Transport Agent (MTA). MTAs deliver
  mail from one machine to another. Sendmail is not a client program, but
  rather a behind-the-scenes daemon that moves email over networks or the
  Internet to its final destination.

  The configuration of sendmail in Red Hat Enterprise Linux was found to not
  reject the &quot;localhost.localdomain&quot; domain name for email messages that come
  from external hosts. This could allow remote attackers to disguise spoofed
  messages. (CVE-2006-7176)
  
  A flaw was found in the way sendmail handled NUL characters in the
  CommonName field of X.509 certificates. An attacker able to get a
  carefully-crafted certificate signed by a trusted Certificate Authority
  could trick sendmail into accepting it by mistake, allowing the attacker to
  perform a man-in-the-middle attack or bypass intended client certificate
  authentication. (CVE-2009-4565)
  
  Note: The CVE-2009-4565 issue only affected configurations using TLS with
  certificate verification and CommonName checking enabled, which is not a
  typical configuration.
  
  This update also fixes the following bugs:
  
  * sendmail was unable to parse files specified by the ServiceSwitchFile
  option which used a colon as a separator. (BZ#512871)
  
  * sendmail incorrectly returned a zero exit code when free space was low.
  (BZ#299951)
  
  * the sendmail manual page had a blank space between the -qG option and
  parameter. (BZ#250552)
  
  * the comments in the sendmail.mc file specified the wrong path to SSL
  certificates. (BZ#244012)
  
  * the sendmail packages did not provide the MTA capability. (BZ#494408)
  
  All users of sendmail are advised to upgrade to these updated packages,
  which resolve these issues.";

tag_affected = "sendmail on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-March/msg00033.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314360");
  script_version("$Revision: 8485 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 08:57:57 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-06 08:56:44 +0200 (Tue, 06 Apr 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2010:0237-05");
  script_cve_id("CVE-2006-7176", "CVE-2009-4565");
  script_name("RedHat Update for sendmail RHSA-2010:0237-05");

  script_tag(name: "summary" , value: "Check for the Version of sendmail");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"sendmail", rpm:"sendmail~8.13.8~8.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sendmail-cf", rpm:"sendmail-cf~8.13.8~8.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sendmail-debuginfo", rpm:"sendmail-debuginfo~8.13.8~8.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sendmail-devel", rpm:"sendmail-devel~8.13.8~8.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sendmail-doc", rpm:"sendmail-doc~8.13.8~8.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
