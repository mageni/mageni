###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for vsftpd RHSA-2008:0680-01
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
tag_insight = "vsftpd (Very Secure File Transfer Protocol (FTP) daemon) is a secure FTP
  server for Linux and Unix-like systems.

  The version of vsftpd as shipped in Red Hat Enterprise Linux 4 when used in
  combination with Pluggable Authentication Modules (PAM) had a memory leak
  on an invalid authentication attempt. Since vsftpd prior to version 2.0.5
  allows any number of invalid attempts on the same connection this memory
  leak could lead to an eventual DoS. (CVE-2008-2375)
  
  This update mitigates this security issue by including a backported patch
  which terminates a session after a given number of failed log in attempts.
  The default number of attempts is 3 and this can be configured using the
  &quot;max_login_fails&quot; directive.
  
  This package also addresses the following bugs:
  
  * when uploading unique files, a bug in vsftpd caused the file to be saved
  with a suffix '.1' even when no previous file with that name existed. This
  issues is resolved in this package.
  
  * when vsftpd was run through the init script, it was possible for the init
  script to print an 'OK' message, even though the vsftpd may not have
  started. The init script no longer produces a false verification with this
  update.
  
  * vsftpd only supported usernames with a maximum length of 32 characters.
  The updated package now supports usernames up to 128 characters long.
  
  * a system flaw meant vsftpd output could become dependent on the timing or
  sequence of other events, even when the &quot;lock_upload_files&quot; option was set.
  If a file, filename.ext, was being uploaded and a second transfer of the
  file, filename.ext, was started before the first transfer was finished, the
  resultant uploaded file was a corrupt concatenation of the latter upload
  and the tail of the earlier upload. With this updated package, vsftpd
  allows the earlier upload to complete before overwriting with the latter
  upload, fixing the issue.
  
  * the 'lock_upload_files' option was not documented in the manual page. A
  new manual page describing this option is included in this package.
  
  * vsftpd did not support usernames that started with an underscore or a
  period character. These special characters are now allowed at the beginning
  of a username.
  
  * when storing a unique file, vsftpd could cause an error for some clients.
  This is rectified in this package.
  
  * vsftpd init script was found to not be Linux Standards Base compliant.
  This update corrects their exit codes to conform to the standard.
  
  All vsftpd users are advised to upgrade to this updated package, which
  resolves these issues.";

tag_affected = "vsftpd on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-July/msg00031.html");
  script_oid("1.3.6.1.4.1.25623.1.0.307771");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_xref(name: "RHSA", value: "2008:0680-01");
  script_cve_id("CVE-2008-2375");
  script_name( "RedHat Update for vsftpd RHSA-2008:0680-01");

  script_tag(name:"summary", value:"Check for the Version of vsftpd");
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

  if ((res = isrpmvuln(pkg:"vsftpd", rpm:"vsftpd~2.0.1~6.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vsftpd-debuginfo", rpm:"vsftpd-debuginfo~2.0.1~6.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
