###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for vsftpd RHSA-2008:0295-01
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
tag_insight = "The vsftpd package includes a Very Secure File Transfer Protocol (FTP)
  daemon.

  A memory leak was discovered in the vsftpd daemon. An attacker who is able
  to connect to an FTP service, either as an authenticated or anonymous user,
  could cause vsftpd to allocate all available memory if the &quot;deny_file&quot;
  option was enabled in vsftpd.conf. (CVE-2007-5962)
  
  As well, this updated package fixes following bugs:
  
  * a race condition could occur even when the &quot;lock_upload_files&quot; option is
  set. When uploading two files simultaneously, the result was a combination
  of the two files. This resulted in uploaded files becoming corrupted. In
  these updated packages, uploading two files simultaneously will result in a
  file that is identical to the last uploaded file.
  
  * when the &quot;userlist_enable&quot; option is used, failed log in attempts as a
  result of the user not being in the list of allowed users, or being in the
  list of denied users, will not be logged. In these updated packages, a new
  &quot;userlist_log=YES&quot; option can be configured in vsftpd.conf, which will log
  failed log in attempts in these situations.
  
  * vsftpd did not support usernames that started with an underscore or a
  period character. Usernames starting with an underscore or a period are
  supported in these updated packages.
  
  * using wildcards in conjunction with the &quot;ls&quot; command did not return all
  the file names it should. For example, if you FTPed into a directory
  containing three files -- A1, A21 and A11 -- and ran the &quot;ls *1&quot; command,
  only the file names A1 and A21 were returned. These updated packages use
  greedier code that continues to speculatively scan for items even after
  matches have been found.
  
  * when the &quot;user_config_dir&quot; option is enabled in vsftpd.conf, and the
  user-specific configuration file did not exist, the following error
  occurred after a user entered their password during the log in process:
  
  500 OOPS: reading non-root config file
  
  This has been resolved in this updated package.
  
  All vsftpd users are advised to upgrade to this updated package, which
  resolves these issues.";

tag_affected = "vsftpd on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-May/msg00018.html");
  script_oid("1.3.6.1.4.1.25623.1.0.307634");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_xref(name: "RHSA", value: "2008:0295-01");
  script_cve_id("CVE-2007-5962");
  script_name( "RedHat Update for vsftpd RHSA-2008:0295-01");

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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"vsftpd", rpm:"vsftpd~2.0.5~12.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vsftpd-debuginfo", rpm:"vsftpd-debuginfo~2.0.5~12.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
