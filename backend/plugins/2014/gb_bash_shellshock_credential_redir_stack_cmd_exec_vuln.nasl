###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bash_shellshock_credential_redir_stack_cmd_exec_vuln.nasl 12551 2018-11-27 14:35:38Z cfischer $
#
# GNU Bash Stacked Redirects aka 'redir_stack' Memory Corruption Vulnerability (LSC)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:gnu:bash";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802083");
  script_version("$Revision: 12551 $");
  script_cve_id("CVE-2014-7186");
  script_bugtraq_id(70152);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-27 15:35:38 +0100 (Tue, 27 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-10-01 13:23:37 +0530 (Wed, 01 Oct 2014)");
  script_name("GNU Bash Stacked Redirects aka 'redir_stack' Memory Corruption Vulnerability (LSC)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_gnu_bash_detect_lin.nasl");
  script_mandatory_keys("bash/linux/detected");
  script_exclude_keys("ssh/force/pty");

  script_xref(name:"URL", value:"https://shellshocker.net/");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2014/09/26/2");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2014/09/25/32");
  script_xref(name:"URL", value:"http://lcamtuf.blogspot.in/2014/09/bash-bug-apply-unofficial-patch-now.html");
  script_xref(name:"URL", value:"http://www.gnu.org/software/bash/");

  script_tag(name:"summary", value:"This host is installed with GNU Bash Shell
  and is prone to command execution vulnerability.");

  script_tag(name:"vuldetect", value:"Login to the target machine with ssh
  credentials and check its possible to execute the commands via GNU bash
  shell.");

  script_tag(name:"insight", value:"GNU bash contains a flaw that is triggered
  when evaluating untrusted input during stacked redirects handling.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to corrupt memory to cause a crash or potentially execute arbitrary
  coommands.");

  script_tag(name:"affected", value:"GNU Bash through 4.3 bash43-026");

  script_tag(name:"solution", value:"Apply the appropriate patch.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

if( get_kb_item( "ssh/force/pty" ) ) exit( 0 );

if( isnull( port = get_app_port( cpe:CPE, service:"ssh-login" ) ) ) exit( 0 );
if( ! bin = get_app_location( cpe:CPE, port:port ) ) exit( 0 ); # Returns e.g. "/bin/bash" or "unknown" (if the location of the binary wasn't detected).

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

if( bin == "unknown" )
  bash_cmd = "bash";
else if( bin =~ "^/.*bash$" )
  bash_cmd = bin;
else
  exit( 0 ); # Safeguard if something is broken in the bash detection

# /bin/bash -c 'true <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF' || echo 'CVE-2014-7186 vulnerable, redir_stack'
cmd = bash_cmd + " -c 'true <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF' || echo 'CVE-2014-7186 vulnerable, redir_stack'";

result = ssh_cmd( socket:sock, cmd:cmd, nosh:TRUE );
close( sock );

if( "In fish, please use" >< result ) exit( 99 );

if( "CVE-2014-7186 vulnerable, redir_stack" >< result ) {
  report = "Used command: " + cmd + '\n\nResult: ' + result;
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );