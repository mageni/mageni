##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mailscanner_infinite_loop_dos_vuln_900413.nasl 14240 2019-03-17 15:50:45Z cfischer $
# Description: MailScanner Infinite Loop Denial of Service Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900413");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-12-10 08:20:26 +0100 (Wed, 10 Dec 2008)");
  script_bugtraq_id(32514);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("Denial of Service");
  script_name("MailScanner Infinite Loop Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/Advisories/32915");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes in a
  crafted message and it can lead to system crash through high CPU resources.");
  script_tag(name:"affected", value:"MailScanner version prior to 4.73.3-1 on all Linux platforms.");
  script_tag(name:"insight", value:"This error is due to an issue in 'Clean' Function in message.pm.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to the latest MailScanner version 4.73.3-1.");

  script_tag(name:"summary", value:"This host is installed with MailScanner and is prone to Denial of
  Service vulnerability.");

  exit(0);
}

include("ssh_func.inc");

sock = ssh_login_or_reuse_connection();
if(sock)
{
  ver = ssh_cmd(socket:sock, cmd:"MailScanner -v", timeout:120);
  ssh_close_connection();
  if("MailScanner" >< ver){
    pattern = "MailScanner version ([0-3](\..*)|4(\.[0-6]?[0-9](\..*)?|\.7[0-2](\..*)?|\.73\.[0-3]))($|[^.0-9])";
    if(egrep(pattern:pattern, string:ver)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
