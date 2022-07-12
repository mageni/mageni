###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_612_2.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for openssh vulnerability USN-612-2
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
tag_insight = "1. Install the security updates

  Ubuntu 7.04:
  openssh-client                  1:4.3p2-8ubuntu1.3
  openssh-server                  1:4.3p2-8ubuntu1.3
  
  Ubuntu 7.10:
  openssh-client                  1:4.6p1-5ubuntu0.3
  openssh-server                  1:4.6p1-5ubuntu0.3
  
  Ubuntu 8.04 LTS:
  openssh-client                  1:4.7p1-8ubuntu1.1
  openssh-server                  1:4.7p1-8ubuntu1.1
  
  Once the update is applied, weak user keys will be automatically
  rejected where possible (though they cannot be detected in all
  cases). If you are using such keys for user authentication,
  they will immediately stop working and will need to be replaced
  (see step 3).
  
  OpenSSH host keys can be automatically regenerated when the
  OpenSSH security update is applied. The update will prompt for
  confirmation before taking this step.
  
  2. Update OpenSSH known_hosts files
  
  The regeneration of host keys will cause a warning to be displayed
  when connecting to the system using SSH until the host key is
  updated in the known_hosts file. The warning will look like this:
  
  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
  @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
  IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
  Someone could be eavesdropping on you right now (man-in-the-middle
  attack)! It is also possible that the RSA host key has just been
  changed.
  
  In this case, the host key has simply been changed, and you
  should update the relevant known_hosts file as indicated in the
  error message.
  
  3. Check all OpenSSH user keys
  
  The safest course of action is to regenerate all OpenSSH user
  keys, except where it can be established to a high degree of
  certainty that the key was generated on an unaffected system.
  
  Check whether your key is affected by running the ssh-vulnkey
  tool, included in the security update. By default, ssh-vulnkey
  will check the standard location for user keys (~/.ssh/id_rsa,
  ~/.ssh/id_dsa and ~/.ssh/identity), your authorized_keys file
  (~/.ssh/authorized_keys and ~/.ssh/authorized_keys2), and the
  system's host keys (/etc/ssh/ssh_host_dsa_key and
  /etc/ssh/ssh_host_rsa_key).
  
  To check all your own keys, assuming they are in the standard
  locations (~/.ssh/id_rsa, ~/.ssh/id_dsa, or ~/.ssh/identity):
  
  $ ssh-vulnkey
  
  To check all keys on your system:
  
  $ sudo ssh-vulnkey -a
  
  To check a key in a non-standard location:
  
  $ ssh-vulnkey /path/to/key
  
  If ssh-vul ... 

  Description truncated, for more information please check the Reference URL";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-612-2";
tag_solution = "Please Install the Updated Packages.";
tag_affected = "openssh vulnerability on Ubuntu 7.04 ,
  Ubuntu 7.10 ,
  Ubuntu 8.04 LTS";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-612-2/");
  script_oid("1.3.6.1.4.1.25623.1.0.309953");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_cve_id("CVE-2008-0166");
  script_name( "Ubuntu Update for openssh vulnerability USN-612-2");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

if(release == "UBUNTU7.04")
{

  if ((res = isdpkgvuln(pkg:"openssh-client", ver:"4.3p2-8ubuntu1.3", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssh-server", ver:"4.3p2-8ubuntu1.3", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ssh-askpass-gnome", ver:"4.3p2-8ubuntu1.3", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ssh", ver:"4.3p2-8ubuntu1.3", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ssh-krb5", ver:"4.3p2-8ubuntu1.3", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"openssh-client", ver:"4.7p1-8ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssh-server", ver:"4.7p1-8ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ssh-askpass-gnome", ver:"4.7p1-8ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ssh", ver:"4.7p1-8ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ssh-krb5", ver:"4.7p1-8ubuntu1.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.10")
{

  if ((res = isdpkgvuln(pkg:"openssh-client", ver:"4.6p1-5ubuntu0.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssh-server", ver:"4.6p1-5ubuntu0.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ssh-askpass-gnome", ver:"4.6p1-5ubuntu0.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ssh", ver:"4.6p1-5ubuntu0.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ssh-krb5", ver:"4.6p1-5ubuntu0.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
